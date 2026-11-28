/* purpose: exercise real-node regtest and Ironwood sync and restart. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/regtest_node_fixture.h"

#define IW_BALLOT "bb447e1ae3827c976f4ff08a5b5ac7379fa486ce1bc13480f3e9db7e0dc733af"
#define IW_FIXTURE "tests/fixtures/ironwood/selected-manifest.json"
#define IW_CMD_MS 120000L
#define IW_BOOT_MS 15000L
#define IW_MINE_MS 50000L
#define IW_SYNC_MS 25000L
#define IW_RESTART_MS 40000L

struct iw_state {
    struct rnf miner, follower;
    char raw[RNF_RAW], address[256], tip[80];
    bool research;
};

static struct iw_state iw;
static volatile sig_atomic_t iw_miner_pid, iw_follower_pid;
static volatile sig_atomic_t iw_rpc_pid;
static struct sigaction iw_old_int, iw_old_term;
static bool iw_armed;
static volatile sig_atomic_t iw_interrupted;
static bool iw_cleanup_failed;
static long iw_title_deadline;
static long iw_title_started;
static int iw_last_height = -1;
static char iw_last_hash[80];
static const char *iw_title_name;
static bool iw_hang_for_test;

static void iw_title_begin(const char *name, long duration)
{
    iw_title_name = name;
    iw_title_started = rnf_now_ms();
    iw_title_deadline = iw_title_started + duration;
    iw_last_height = -1;
    iw_last_hash[0] = '\0';
}

static long iw_remaining(const char *step, long cap)
{
    if (iw_interrupted) {
        printf("INTERRUPTED title=%s step=%s signal=%d\n",
               iw_title_name ? iw_title_name : "unknown", step,
               (int)iw_interrupted);
        return 0;
    }
    long now = rnf_now_ms();
    long remaining = iw_title_deadline - now;
    if (remaining <= 0) {
        printf("DEADLINE title=%s step=%s elapsed_ms=%ld last_height=%d last_hash=%s\n",
               iw_title_name ? iw_title_name : "unknown", step,
               now - iw_title_started, iw_last_height, iw_last_hash);
        return 0;
    }
    return remaining < cap ? remaining : cap;
}

static void iw_signal(int sig)
{
    iw_interrupted = sig;
}

static bool iw_reap_until(pid_t pid, long deadline, int *status)
{
    while (rnf_now_ms() < deadline) {
        pid_t got = waitpid(pid, status, WNOHANG);
        if (got == pid || (got < 0 && errno == ECHILD)) return true;
        if (got < 0 && errno != EINTR) return false;
        rnf_sleep_ms(20);
    }
    return false;
}

static bool iw_terminate(pid_t pid, int *status)
{
    if (pid <= 0) return true;
    (void)kill(-pid, SIGTERM);
    if (iw_reap_until(pid, rnf_now_ms() + 1000, status)) {
        (void)kill(-pid, SIGKILL);
        return true;
    }
    (void)kill(-pid, SIGKILL);
    if (iw_reap_until(pid, rnf_now_ms() + 2000, status)) return true;
    fprintf(stderr, "could not reap process group %ld\n", (long)pid);
    return false;
}

static bool iw_cleanup_node(struct rnf *node)
{
    if (node->node <= 0) return true;
    int status = 0;
    if (!iw_terminate(node->node, &status)) return false;
    node->node = 0;
    return true;
}

static void iw_remove_fixture(struct rnf *node)
{
    if (!node->work[0]) return;
    if (test_rm_rf_recursive(node->work) != 0) {
        fprintf(stderr, "fixture cleanup failed: %s\n", node->work);
        iw_cleanup_failed = true;
        return;
    }
    node->work[0] = '\0';
}

static void iw_cleanup(void)
{
    if (!iw_cleanup_node(&iw.miner)) iw_cleanup_failed = true;
    iw_miner_pid = 0;
    if (!iw_cleanup_node(&iw.follower)) iw_cleanup_failed = true;
    iw_follower_pid = 0;
    if (iw_rpc_pid > 0) {
        int status = 0;
        if (!iw_terminate((pid_t)iw_rpc_pid, &status)) iw_cleanup_failed = true;
        else iw_rpc_pid = 0;
    }
    if (iw_armed) {
        sigaction(SIGINT, &iw_old_int, NULL);
        sigaction(SIGTERM, &iw_old_term, NULL);
        iw_armed = false;
    }
    if (!iw_cleanup_failed) {
        iw_remove_fixture(&iw.miner);
        iw_remove_fixture(&iw.follower);
    }
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

static bool iw_setup(struct rnf *e, const char *tag)
{
    memset(e, 0, sizeof(*e));
    if (!test_mkdtemp(e->work, sizeof(e->work), tag)) {
        e->work[0] = '\0';
        return false;
    }
    char datadir[PATH_MAX + 16];
    snprintf(datadir, sizeof(datadir), "%s/datadir", e->work);
    snprintf(e->cred, sizeof(e->cred), "%s/cred", e->work);
    if (mkdir(datadir, 0700) != 0 || mkdir(e->cred, 0700) != 0)
        return false;
    int n = snprintf(e->dd_flag, sizeof(e->dd_flag), "-datadir=%s", datadir);
    return n > 0 && (size_t)n < sizeof(e->dd_flag);
}

static bool iw_prepare(struct rnf *e, const char *tag)
{
    if (!iw_setup(e, tag)) return false;
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
    if (iw_remaining("start node", 1) == 0) return false;
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) iw_node_child(e, peer, parent);
    setpgid(pid, pid);
    e->node = pid;
    *slot = (sig_atomic_t)pid;
    return true;
}

static void iw_exec_child(const struct rnf *e, const char *const *words, int *p,
                          pid_t parent)
{
    if (!rnf_child_die_with_parent(parent)) _exit(127);
    (void)setpgid(0, 0);
    if (iw_hang_for_test) {
        sleep(2); /* real-clock: deliberately stalled child for deadline test */
        _exit(0);
    }
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
        if (got < 0 && errno != EINTR) return -1;
        if (iw_interrupted) break;
        rnf_sleep_ms(50);
    }
    printf("RPC deadline expired, terminating pid %ld\n", (long)pid);
    if (!iw_terminate(pid, &status)) iw_cleanup_failed = true;
    return -1;
}

static int iw_call(struct rnf *e, const char *const *words)
{
    long remaining = iw_remaining(words[0], IW_CMD_MS);
    if (remaining <= 0 || iw_interrupted) return -1;
    int p[2];
    iw.raw[0] = '\0';
    printf("RPC %s waiting\n", words[0]);
    fflush(stdout);
    if (pipe(p) != 0) return -1;
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) iw_exec_child(e, words, p, parent);
    (void)setpgid(pid, pid);
    iw_rpc_pid = pid;
    close(p[1]);
    /* real-clock: bound the external RPC and report its reply or timeout. */
    long deadline = rnf_now_ms() + remaining;
    rnf_read_until(p[0], iw.raw, sizeof(iw.raw), deadline);
    close(p[0]);
    int rc = iw_wait_child(pid, deadline);
    (void)kill(-pid, SIGKILL);
    if (!iw_cleanup_failed) iw_rpc_pid = 0;
    if (rc != 0) (void)iw_remaining(words[0], IW_CMD_MS);
    printf("RPC %s rc=%d raw:\n%s\n", words[0], rc, iw.raw);
    fflush(stdout);
    return rc;
}

static bool iw_clean_reply(int rc)
{
    return !iw_interrupted && rc == 0 && strstr(iw.raw, "error") == NULL &&
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
    while (iw_remaining("readiness", 500) > 0) {
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
        long pause = iw_remaining("readiness", 500);
        if (pause > 0) rnf_sleep_ms(pause);
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
    if (strlen(hash) != 64) return false;
    iw_last_height = *height;
    snprintf(iw_last_hash, sizeof(iw_last_hash), "%s", hash);
    return true;
}

static bool iw_agree(int expected, const char *expected_hash)
{
    /* real-clock: bound independent-node synchronization polling. */
    while (iw_remaining("sync", 500) > 0) {
        int a = -1, b = -1;
        char ah[80] = "", bh[80] = "";
        bool miner = iw_chain(&iw.miner, &a, ah, sizeof(ah));
        bool follower = iw_chain(&iw.follower, &b, bh, sizeof(bh));
        printf("sync poll miner=%d %s follower=%d %s expected=%d %s\n",
               a, ah, b, bh, expected, expected_hash);
        if (miner && follower && a == expected && b == expected &&
            strcmp(ah, expected_hash) == 0 && strcmp(ah, bh) == 0) return true;
        if (iw_interrupted) return false;
        long pause = iw_remaining("sync", 500);
        if (pause > 0) rnf_sleep_ms(pause);
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
    long remaining = iw_remaining("stop", 60000L);
    long deadline = rnf_now_ms() + remaining;
    int rc = iw_wait_child(pid, deadline);
    if (rc != 0) (void)iw_remaining("stop", 1);
    (void)kill(-pid, SIGKILL);
    if (!iw_cleanup_failed) {
        node->node = 0;
        *slot = 0;
    }
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
    iw_title_begin("boot", IW_BOOT_MS);
    TEST(iw.research ? "research boot" : "regtest boot") {
        ASSERT(iw_prepare(&iw.miner, "ironwood_miner"));
        ASSERT(iw_prepare(&iw.follower, "ironwood_follower"));
        ASSERT(iw_ports());
        ASSERT(iw_start(&iw.miner, 0, &iw_miner_pid));
        ASSERT(iw_wait_up(&iw.miner));
        ASSERT(iw_chain(&iw.miner, &height, hash, sizeof(hash)));
        ASSERT_EQ(height, 0);
        ASSERT(iw_remaining("boot complete", 1) > 0);
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
    iw_title_begin("mine", IW_MINE_MS);
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
        ASSERT(iw_remaining("mine complete", 1) > 0);
        PASS();
    } _test_next:;
    return failures;
}

static int iw_sync(void)
{
    int failures = 0;
    iw_title_begin("sync", IW_SYNC_MS);
    TEST(iw.research ? "research sync" : "regtest sync") {
        ASSERT(iw_start(&iw.follower, iw.miner.port[0], &iw_follower_pid));
        ASSERT(iw_wait_up(&iw.follower));
        ASSERT(iw_agree(101, iw.tip));
        printf("SYNC height=101 hash=%s\n", iw.tip);
        ASSERT(iw_remaining("sync complete", 1) > 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool iw_recovered(struct rnf *node)
{
    const char *const peers[] = { "getpeerinfo", NULL };
    int height = -1;
    char hash[80];
    if (!iw_clean_reply(iw_call(node, peers)) || strcmp(iw.raw, "[]\n") != 0)
        return false;
    if (!iw_chain(node, &height, hash, sizeof(hash)))
        return false;
    printf("ISOLATED_RECOVERY height=%d hash=%s expected=%s\n", height, hash, iw.tip);
    return height == 101 && strcmp(hash, iw.tip) == 0;
}

static bool iw_peer(struct rnf *node, const char *address, bool prefix)
{
    const char *const peers[] = { "getpeerinfo", NULL };
    if (!iw_clean_reply(iw_call(node, peers))) return false;
    struct json_value doc;
    if (!rnf_parse(iw.raw, &doc)) return false;
    bool ok = doc.type == JSON_ARR && doc.num_children == 1;
    if (ok) {
        const char *seen = rnf_str(&doc.children[0], "addr");
        ok = prefix ? strncmp(seen, address, strlen(address)) == 0
                    : strcmp(seen, address) == 0;
    }
    json_free(&doc);
    return ok;
}

static bool iw_reconnected(const char *peer)
{
    while (iw_remaining("reconnect peers", 1) > 0) {
        bool follower = iw_peer(&iw.follower, peer, false);
        bool miner = iw_peer(&iw.miner, "127.0.0.1:", true);
        if (follower && miner) return true;
        if (iw_remaining("reconnect peers", 1) > 0) rnf_sleep_ms(100);
    }
    return false;
}

static bool iw_miner_tip(int expected)
{
    while (iw_remaining("mined tip", 1) > 0) {
        int height = -1;
        if (iw_chain(&iw.miner, &height, iw.tip, sizeof(iw.tip)) &&
            height == expected) return true;
        if (iw_remaining("mined tip", 1) > 0) rnf_sleep_ms(100);
    }
    return false;
}

static int iw_restart(void)
{
    int failures = 0;
    char peer[64];
    snprintf(peer, sizeof(peer), "127.0.0.1:%u", iw.miner.port[0]);
    const char *const connect[] = { "addnode", peer, "onetry", NULL };
    iw_title_begin("restart", IW_RESTART_MS);
    TEST(iw.research ? "research restart" : "regtest restart") {
        ASSERT(iw_stop(&iw.follower, &iw_follower_pid));
        ASSERT(iw_stop(&iw.miner, &iw_miner_pid));
        ASSERT(iw_start(&iw.miner, 0, &iw_miner_pid));
        ASSERT(iw_wait_up(&iw.miner));
        ASSERT(iw_recovered(&iw.miner));
        ASSERT(iw_start(&iw.follower, 0, &iw_follower_pid));
        ASSERT(iw_wait_up(&iw.follower));
        ASSERT(iw_recovered(&iw.follower));
        ASSERT(iw_clean_reply(iw_call(&iw.follower, connect)));
        ASSERT(iw_reconnected(peer));
        ASSERT(iw_mine_batch("1", 1));
        ASSERT(iw_miner_tip(102));
        ASSERT(iw_agree(102, iw.tip));
        printf("RESTART height=102 hash=%s peers=1/1\n", iw.tip);
        ASSERT(iw_remaining("restart complete", 1) > 0);
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

static int iw_test_failed_setup_cleanup(void)
{
    int failures = 0;
    iw_title_begin("failed setup cleanup", IW_BOOT_MS);
    TEST("fixture failed setup preserves unowned template") {
        char root[PATH_MAX] = "", template[PATH_MAX + 64], old[PATH_MAX];
        const char *env = getenv("ZCL_TEST_TMPROOT");
        bool had_root = env && *env;
        snprintf(old, sizeof(old), "%s", had_root ? env : "");
        bool made_root = test_mkdtemp(root, sizeof(root), "iw_cleanup_probe");
        snprintf(template, sizeof(template), "%s/ironwood_miner_XXXXXX", root);
        bool made_template = made_root && mkdir(template, 0700) == 0;
        bool restricted = made_template && chmod(root, 0755) == 0;
        bool configured = restricted && setenv("ZCL_TEST_TMPROOT", root, 1) == 0;
        memset(&iw, 0, sizeof(iw));
        bool failed = configured && !iw_prepare(&iw.miner, "ironwood_miner");
        iw_cleanup();
        bool survived = access(template, F_OK) == 0;
        if (had_root) (void)setenv("ZCL_TEST_TMPROOT", old, 1);
        else (void)unsetenv("ZCL_TEST_TMPROOT");
        if (made_root) {
            (void)chmod(root, 0700);
            (void)test_rm_rf_recursive(root);
        }
        ASSERT(made_root && made_template && restricted && configured);
        ASSERT(failed);
        ASSERT(survived);
        ASSERT(iw_remaining("failed setup cleanup complete", 1) > 0);
        PASS();
    } _test_next:;
    return failures;
}

static int iw_test_quoted_cleanup(void)
{
    int failures = 0;
    iw_title_begin("quoted cleanup", IW_BOOT_MS);
    TEST("fixture cleanup handles apostrophe and is idempotent") {
        char root[PATH_MAX] = "", quoted[PATH_MAX + 32], owned[PATH_MAX];
        char old[PATH_MAX];
        const char *env = getenv("ZCL_TEST_TMPROOT");
        bool had_root = env && *env;
        snprintf(old, sizeof(old), "%s", had_root ? env : "");
        bool made_root = test_mkdtemp(root, sizeof(root), "iw_quote_probe");
        snprintf(quoted, sizeof(quoted), "%s/quote'root", root);
        bool ready = made_root && mkdir(quoted, 0700) == 0 &&
                     setenv("ZCL_TEST_TMPROOT", quoted, 1) == 0;
        memset(&iw, 0, sizeof(iw));
        bool created = ready && iw_setup(&iw.miner, "quoted");
        snprintf(owned, sizeof(owned), "%s", iw.miner.work);
        iw_cleanup();
        iw_cleanup();
        bool removed = created && access(owned, F_OK) != 0 && errno == ENOENT;
        if (had_root) (void)setenv("ZCL_TEST_TMPROOT", old, 1);
        else (void)unsetenv("ZCL_TEST_TMPROOT");
        if (made_root) (void)test_rm_rf_recursive(root);
        ASSERT(made_root && ready);
        ASSERT(removed);
        ASSERT(!iw_cleanup_failed);
        ASSERT(iw_remaining("quoted cleanup complete", 1) > 0);
        PASS();
    } _test_next:;
    return failures;
}

static int iw_test_rpc_deadline(void)
{
    int failures = 0;
    TEST("hung RPC respects the title deadline") {
        const char *const words[] = { "getblockcount", NULL };
        long start = rnf_now_ms();
        iw_title_begin("hung RPC", 250);
        printf("HUNG_RPC deadline_ms=%ld\n", iw_title_deadline - start);
        iw_hang_for_test = true;
        int rc = iw_call(&iw.miner, words);
        long elapsed = rnf_now_ms() - start;
        iw_hang_for_test = false;
        iw_title_deadline = 0;
        printf("HUNG_RPC elapsed_ms=%ld rc=%d\n", elapsed, rc);
        ASSERT(rc != 0);
        ASSERT(elapsed < 1000);
        PASS();
    } _test_next:;
    return failures;
}

static bool iw_ready_byte(int fd, long ms)
{
    struct pollfd p = { .fd = fd, .events = POLLIN };
    char byte;
    return poll(&p, 1, (int)ms) > 0 && (p.revents & POLLIN) &&
           read(fd, &byte, 1) == 1;
}

/* Child side of a readiness pipe: one byte, then the caller waits. When the
 * byte cannot be written the child ends, so the parent sees end-of-file at
 * its bounded poll instead of a child that waits forever. */
static void iw_ready_signal(int fd)
{
    if (write(fd, "R", 1) != 1)
        _exit(127);
}

static int iw_test_signal_flag_only(void)
{
    int failures = 0;
    TEST("interrupt handler leaves child cleanup to main flow") {
        int ready[2];
        ASSERT(pipe(ready) == 0);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            close(ready[0]);
            (void)setpgid(0, 0);
            (void)signal(SIGTERM, SIG_IGN);
            iw_ready_signal(ready[1]);
            for (;;) pause();
        }
        (void)setpgid(pid, pid);
        close(ready[1]);
        bool started = iw_ready_byte(ready[0], IW_BOOT_MS);
        close(ready[0]);
        iw_miner_pid = pid;
        iw_signal(SIGTERM);
        rnf_sleep_ms(100); /* real-clock: allow the old handler's kill to land */
        int status = 0;
        bool alive = waitpid(pid, &status, WNOHANG) == 0;
        bool reaped = !alive || iw_terminate(pid, &status);
        iw_miner_pid = 0;
        bool flagged = iw_interrupted == SIGTERM;
        bool refuses_success = !iw_clean_reply(0) &&
                               iw_remaining("interrupt test", 1) == 0;
        iw_interrupted = 0;
        printf("INTERRUPT_TEST alive=%d reaped=%d killed=%d\n", alive, reaped,
               WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        ASSERT(started && flagged && alive && reaped && refuses_success &&
               WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        PASS();
    } _test_next:;
    return failures;
}

static int iw_test_stop_deadline(void)
{
    int failures = 0;
    TEST("stop deadline escalates and reaps") {
        int ready[2];
        ASSERT(pipe(ready) == 0);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            close(ready[0]);
            (void)setpgid(0, 0);
            (void)signal(SIGTERM, SIG_IGN);
            iw_ready_signal(ready[1]);
            for (;;) pause();
        }
        (void)setpgid(pid, pid);
        close(ready[1]);
        bool started = iw_ready_byte(ready[0], IW_BOOT_MS);
        close(ready[0]);
        struct rnf node = {0};
        volatile sig_atomic_t slot = pid;
        node.node = pid;
        iw_title_begin("stop test", 250);
        bool stopped_cleanly = iw_stop(&node, &slot);
        int status;
        bool reaped = waitpid(pid, &status, WNOHANG) < 0 && errno == ECHILD;
        printf("STOP_TEST started=%d clean=%d reaped=%d\n",
               started, stopped_cleanly, reaped);
        ASSERT(started && !stopped_cleanly && reaped);
        PASS();
    } _test_next:;
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
    int failures = iw_test_failed_setup_cleanup();
    failures += iw_test_quoted_cleanup();
    failures += iw_test_rpc_deadline();
    failures += iw_test_signal_flag_only();
    failures += iw_test_stop_deadline();
    if (failures) return failures;
    atexit(iw_cleanup);
    iw_arm();
    failures = iw_run_profile(false);
    if (!iw_interrupted) {
        iw_arm();
        failures += iw_run_profile(true);
    }
    if (iw_interrupted || iw_cleanup_failed) failures++;
    return failures;
}
