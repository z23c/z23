/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_private_listeners — the -private-listeners node option.
 *
 * A node the phone app starts must bind no socket reachable from another
 * address. The argv cases pin the parse and the refusal. The process cases
 * start the real node binary on an isolated regtest datadir, read its
 * listening sockets from /proc/net/tcp and /proc/net/tcp6 by socket inode,
 * and require every one to be loopback, with the HTTPS explorer, the file
 * service, the beta6 side listener and the RPC TLS listener absent and the
 * NAT probe off, and re-read them after boot settles. A node
 * started without the option must still hold its public listeners.
 *
 * The process cases need build/bin/zclassic23 and fail when it is missing.
 *
 * make t-fast ONLY=private_listeners */

#include "test/test_core.h"
#include "config/args.h"
#include "config/boot.h"

#if defined(__linux__)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#define PL_NODE_BIN "build/bin/zclassic23"

static int pl_parse(char **argv, int argc, struct app_context *ctx)
{
    bool show_metrics = false;
    app_context_defaults(ctx);
    return args_parse_node_options(argc, argv, ctx, &show_metrics);
}

/* One case per function: the TEST macro's failure label is function-scoped. */
#define PL_CASE(fn, name) static int fn(void) { int failures = 0; struct app_context ctx; (void)ctx; TEST(name) {
#define PL_END PASS(); } _test_next:; return failures; }

PL_CASE(pl_args_default_bind, "private_listeners: the option binds P2P to 127.0.0.1 by default")
    char *plain[] = {"z23", "-private-listeners"};
    ASSERT(pl_parse(plain, 2, &ctx) == -1);
    ASSERT(ctx.private_listeners);
    ASSERT(ctx.p2p_bind_address && !strcmp(ctx.p2p_bind_address, "127.0.0.1"));
PL_END

PL_CASE(pl_args_loopback_bind, "private_listeners: a loopback -bind= is kept, in either order")
    char *loopback6[] = {"z23", "-private-listeners", "-bind=::1", "-no-tor"};
    char *loopback4[] = {"z23", "-bind=127.0.0.1", "-private-listeners"};
    ASSERT(pl_parse(loopback6, 4, &ctx) == -1);
    ASSERT(!strcmp(ctx.p2p_bind_address, "::1"));
    ASSERT(pl_parse(loopback4, 3, &ctx) == -1);
    ASSERT(!strcmp(ctx.p2p_bind_address, "127.0.0.1"));
PL_END

PL_CASE(pl_args_public_bind, "private_listeners: a non-loopback -bind= is refused")
    char *wildcard[] = {"z23", "-private-listeners", "-bind=0.0.0.0"};
    char *lan[] = {"z23", "-bind=192.168.1.20", "-private-listeners"};
    ASSERT(pl_parse(wildcard, 3, &ctx) == 1);
    ASSERT(pl_parse(lan, 3, &ctx) == 1);
PL_END

PL_CASE(pl_args_off, "private_listeners: off by default, P2P bind untouched")
    char *off[] = {"z23"};
    ASSERT(pl_parse(off, 1, &ctx) == -1);
    ASSERT(!ctx.private_listeners);
    ASSERT(ctx.p2p_bind_address == NULL);
PL_END

PL_CASE(pl_args_refusal, "private_listeners: the pure refusal ignores a node without the option")
    app_context_defaults(&ctx);
    ctx.p2p_bind_address = "0.0.0.0";
    ASSERT(app_private_listeners_refusal(&ctx, true) == NULL);
    ctx.private_listeners = true;
    ASSERT(app_private_listeners_refusal(&ctx, true) != NULL);
    ctx.p2p_bind_address = "127.0.0.1";
    ASSERT(app_private_listeners_refusal(&ctx, true) == NULL);
PL_END

PL_CASE(pl_args_ipv6_tor, "private_listeners: -bind=::1 is refused while Tor runs, accepted without it")
    app_context_defaults(&ctx);
    ctx.private_listeners = true;
    ctx.p2p_bind_address = "::1";
    ASSERT(app_private_listeners_refusal(&ctx, true) != NULL);
    ASSERT(app_private_listeners_refusal(&ctx, false) == NULL);
    ctx.no_tor = true;
    ASSERT(app_private_listeners_refusal(&ctx, true) == NULL);
PL_END

PL_CASE(pl_args_spellings, "private_listeners: --private-listeners and -private-listeners=1 are refused")
    char *dashes[] = {"z23", "--private-listeners"};
    char *value[] = {"z23", "-private-listeners=1"};
    char *dashes_value[] = {"z23", "--private-listeners=1"};
    ASSERT(pl_parse(dashes, 2, &ctx) == 1);
    ASSERT(pl_parse(value, 2, &ctx) == 1);
    ASSERT(pl_parse(dashes_value, 2, &ctx) == 1);
PL_END

PL_CASE(pl_args_observation, "private_listeners: the option turns /observation.json off")
    char *plain[] = {"z23", "-private-listeners"};
    char *off[] = {"z23"};
    char *explicit_on[] = {"z23", "-private-listeners", "-observation=1"};
    ASSERT(pl_parse(off, 1, &ctx) == -1 && !ctx.observation_off);
    ASSERT(pl_parse(plain, 2, &ctx) == -1 && ctx.observation_off);
    ASSERT(pl_parse(explicit_on, 3, &ctx) == -1 && ctx.observation_off);
PL_END

static int test_private_listeners_args(void)
{
    return pl_args_default_bind() + pl_args_loopback_bind() + pl_args_public_bind() +
           pl_args_off() + pl_args_refusal() + pl_args_ipv6_tor() + pl_args_spellings() +
           pl_args_observation();
}

#if defined(__linux__)

#define PL_MAX_SOCKETS 64
#define PL_BOOT_WAIT_MS 90000

struct pl_socket {
    uint8_t address[16];
    bool v6;
    uint16_t port;
};

struct pl_ports {
    uint16_t p2p, rpc, https, http, fs, tls, beta6;
};

struct pl_node {
    pid_t pid;
    bool private_listeners;
    int public_seen;
    char directory[PATH_MAX];
    char log[PATH_MAX];
    struct pl_ports ports;
};

static long pl_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void pl_sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000};
    nanosleep(&ts, NULL);
}

/* Ports the kernel just handed out, none of them a low port. */
static bool pl_free_port(uint16_t *out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(sa);
    bool ok = fd >= 0 && bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0 &&
              getsockname(fd, (struct sockaddr *)&sa, &len) == 0;
    if (ok) *out = ntohs(sa.sin_port);
    if (fd >= 0) close(fd);
    return ok;
}

/* The HTTP redirect port is the HTTPS port minus 363, so both must be free. */
static bool pl_reserve_ports(struct pl_ports *ports)
{
    for (int attempt = 0; attempt < 64; attempt++) {
        uint16_t https = 0, http = 0;
        if (!pl_free_port(&https) || https < 2048) continue;
        http = (uint16_t)(https - 363);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(http),
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        bool http_free = fd >= 0 && bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
        if (fd >= 0) close(fd);
        if (!http_free) continue;
        ports->https = https;
        ports->http = http;
        return pl_free_port(&ports->p2p) && pl_free_port(&ports->rpc) &&
               pl_free_port(&ports->fs) && pl_free_port(&ports->tls) &&
               pl_free_port(&ports->beta6);
    }
    return false;
}

static bool pl_hex(const char *text, size_t digits, uint32_t *out)
{
    uint32_t value = 0;
    for (size_t i = 0; i < digits; i++) {
        char c = text[i];
        uint32_t d = c >= '0' && c <= '9' ? (uint32_t)(c - '0') :
                     c >= 'A' && c <= 'F' ? (uint32_t)(c - 'A' + 10) :
                     c >= 'a' && c <= 'f' ? (uint32_t)(c - 'a' + 10) : 16u;
        if (d > 15) return false;
        value = value << 4 | d;
    }
    *out = value;
    return true;
}

/* /proc/net/tcp prints each 32-bit group in host order; this reads them as
 * little-endian so the bytes come out in network order. */
static bool pl_decode(const char *text, bool v6, struct pl_socket *socket)
{
    size_t groups = v6 ? 4 : 1;
    if (strlen(text) < groups * 8 + 5 || text[groups * 8] != ':') return false;
    for (size_t g = 0; g < groups; g++) {
        uint32_t word;
        if (!pl_hex(text + g * 8, 8, &word)) return false;
        for (size_t b = 0; b < 4; b++)
            socket->address[g * 4 + b] = (uint8_t)(word >> (8 * b));
    }
    uint32_t port;
    if (!pl_hex(text + groups * 8 + 1, 4, &port)) return false;
    socket->v6 = v6;
    socket->port = (uint16_t)port;
    return true;
}

static bool pl_loopback(const struct pl_socket *s)
{
    if (!s->v6) return s->address[0] == 127;
    static const uint8_t zeros[10] = {0};
    if (memcmp(s->address, zeros, 10) != 0) return false;
    if (s->address[10] == 0xff && s->address[11] == 0xff) return s->address[12] == 127;
    for (size_t i = 10; i < 15; i++) if (s->address[i]) return false;
    return s->address[15] == 1;
}

static size_t pl_inodes(pid_t pid, unsigned long *inodes, size_t cap)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
    DIR *dir = opendir(path);
    if (!dir) return 0;
    size_t n = 0;
    struct dirent *entry;
    while (n < cap && (entry = readdir(dir))) {
        char link[128], target[128];
        snprintf(link, sizeof(link), "%s/%s", path, entry->d_name);
        ssize_t len = readlink(link, target, sizeof(target) - 1);
        unsigned long inode;
        if (len <= 0) continue;
        target[len] = '\0';
        if (sscanf(target, "socket:[%lu]", &inode) == 1) inodes[n++] = inode;
    }
    closedir(dir);
    return n;
}

/* Every TCP socket in LISTEN state that the process holds. */
static size_t pl_listeners(pid_t pid, struct pl_socket *out, size_t cap)
{
    unsigned long inodes[1024];
    size_t held = pl_inodes(pid, inodes, 1024), n = 0;
    for (int family = 0; family < 2; family++) {
        FILE *f = fopen(family ? "/proc/net/tcp6" : "/proc/net/tcp", "r");
        char line[512];
        if (!f) continue;
        if (!fgets(line, sizeof(line), f)) { fclose(f); continue; }
        while (n < cap && fgets(line, sizeof(line), f)) {
            char local[64];
            unsigned state;
            unsigned long inode;
            if (sscanf(line, " %*d: %63s %*s %x %*s %*s %*s %*s %*s %lu",
                       local, &state, &inode) != 3 || state != 0x0A) continue;
            bool mine = false;
            for (size_t i = 0; i < held; i++) mine = mine || inodes[i] == inode;
            if (mine && pl_decode(local, family == 1, &out[n])) n++;
        }
        fclose(f);
    }
    return n;
}

static const struct pl_socket *pl_find(const struct pl_socket *s, size_t n, uint16_t port)
{
    for (size_t i = 0; i < n; i++) if (s[i].port == port) return &s[i];
    return NULL;
}

static size_t pl_public(const struct pl_socket *s, size_t n)
{
    size_t count = 0;
    for (size_t i = 0; i < n; i++) if (!pl_loopback(&s[i])) count++;
    return count;
}

/* A throwaway certificate and key for the RPC TLS listener. */
static bool pl_write_certificate(const char *cert_path, const char *key_path)
{
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    X509 *x509 = pkey ? X509_new() : NULL;
    bool ok = false;
    if (x509) {
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_getm_notBefore(x509), 0);
        X509_gmtime_adj(X509_getm_notAfter(x509), 3600);
        X509_set_pubkey(x509, pkey);
        X509_NAME *name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *)"localhost", -1, -1, 0);
        X509_set_issuer_name(x509, name);
        X509_sign(x509, pkey, EVP_sha256());
        FILE *cf = fopen(cert_path, "w"), *kf = fopen(key_path, "w");
        ok = cf && kf && PEM_write_X509(cf, x509) == 1 &&
             PEM_write_PrivateKey(kf, pkey, NULL, NULL, 0, NULL, NULL) == 1;
        if (cf) fclose(cf);
        if (kf) fclose(kf);
    }
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return ok;
}

/* A complete beta6 serve tree and its .anchor sidecar, so the node arms and
 * would open the side listener the environment names. */
static bool pl_write_beta6_source(const char *root)
{
    char path[PATH_MAX + 32];
    static const char *const files[] = {"blocks", "blocks/index", "chainstate"};
    for (size_t i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/%s", root, files[i]);
        if (mkdir(path, 0700) && errno != EEXIST) return false;
    }
    static const char *const data[] = {"blocks/blk00000.dat", "blocks/index/000001.ldb",
                                       "chainstate/000001.ldb"};
    for (size_t i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/%s", root, data[i]);
        FILE *f = fopen(path, "w");
        if (!f || fputs("x", f) < 0 || fclose(f)) return false;
    }
    snprintf(path, sizeof(path), "%s.anchor", root);
    FILE *f = fopen(path, "w");
    bool ok = f && fputs("3126937 00000663e40f1fe0bc32a7e7282fac25de5fe8ecefd9c627e2fd948d388f7053\n", f) >= 0;
    return f && fclose(f) == 0 && ok;
}

static bool pl_start(struct pl_node *node, bool private_listeners)
{
    memset(node, 0, sizeof(*node));
    node->private_listeners = private_listeners;
    if (!test_ensure_tmproot() || !pl_reserve_ports(&node->ports)) return false;
    test_fmt_tmpdir(node->directory, sizeof(node->directory), "zcl_private_listeners",
                    private_listeners ? "private" : "public");
    char data[PATH_MAX + 16], home[PATH_MAX + 16], cert[PATH_MAX + 8], key[PATH_MAX + 8];
    char beta6[PATH_MAX + 16];
    snprintf(data, sizeof(data), "%s/data", node->directory);
    snprintf(home, sizeof(home), "%s/home", node->directory);
    snprintf(node->log, sizeof(node->log), "%s/console.log", node->directory);
    snprintf(beta6, sizeof(beta6), "%s/beta6", node->directory);
    snprintf(cert, sizeof(cert), "%s/rpc-cert.pem", node->directory);
    snprintf(key, sizeof(key), "%s/rpc-key.pem", node->directory);
    if ((mkdir(node->directory, 0700) && errno != EEXIST) ||
        (mkdir(data, 0700) && errno != EEXIST) ||
        (mkdir(home, 0700) && errno != EEXIST) || (mkdir(beta6, 0700) && errno != EEXIST) ||
        !pl_write_beta6_source(beta6) || !pl_write_certificate(cert, key))
        return false;

    char datadir[PATH_MAX + 16], rpc[32], p2p[32], https[32], fs[32];
    char env_home[PATH_MAX + 16], env_cert[PATH_MAX + 32], env_key[PATH_MAX + 32], env_port[48], env_source[PATH_MAX + 48], env_listen[64];
    snprintf(datadir, sizeof(datadir), "-datadir=%s", data);
    snprintf(rpc, sizeof(rpc), "-rpcport=%u", node->ports.rpc);
    snprintf(p2p, sizeof(p2p), "-port=%u", node->ports.p2p);
    snprintf(https, sizeof(https), "-httpsport=%u", node->ports.https);
    snprintf(fs, sizeof(fs), "-fsport=%u", node->ports.fs);
    snprintf(env_home, sizeof(env_home), "HOME=%s", home);
    snprintf(env_cert, sizeof(env_cert), "ZCL_RPC_TLS_CERT=%s", cert);
    snprintf(env_key, sizeof(env_key), "ZCL_RPC_TLS_KEY=%s", key);
    snprintf(env_port, sizeof(env_port), "ZCL_RPC_TLS_PORT=%u", node->ports.tls);
    snprintf(env_source, sizeof(env_source), "ZCL_BETA6_BOOTSTRAP_SOURCE=%s", beta6);
    snprintf(env_listen, sizeof(env_listen), "ZCL_BETA6_BOOTSTRAP_LISTEN=0.0.0.0:%u", node->ports.beta6);
    char *argv[] = {(char *)PL_NODE_BIN, datadir, (char *)"-regtest", rpc, p2p, https, fs,
                    (char *)"-no-tor", (char *)"-nolegacyimport", (char *)"-nobgvalidation",
                    (char *)"-private-listeners", NULL};
    if (!private_listeners) argv[10] = NULL;
    char *envp[] = {env_home, (char *)"PATH=/usr/bin:/bin", env_cert, env_key, env_port,
                    env_source, env_listen, NULL};

    node->pid = fork();
    if (node->pid < 0) return false;
    if (node->pid == 0) {
        int fd = open(node->log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int null = open("/dev/null", O_RDONLY);
        if (fd < 0 || null < 0) _exit(126);
        dup2(null, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        execve(PL_NODE_BIN, argv, envp);
        _exit(127);
    }
    return true;
}

static void pl_stop(struct pl_node *node)
{
    if (node->pid > 0) {
        int status;
        kill(node->pid, SIGKILL);
        waitpid(node->pid, &status, 0);
        node->pid = 0;
    }
}

static bool pl_log_has(const struct pl_node *node, const char *needle)
{
    FILE *f = fopen(node->log, "r");
    char line[1024];
    bool found = false;
    while (f && !found && fgets(line, sizeof(line), f)) found = strstr(line, needle) != NULL;
    if (f) fclose(f);
    return found;
}

/* Boot is complete when the console prints the services_running -> ready
 * stage change, the RPC and P2P sockets are open, and the beta6 arming thread
 * has reached its side-listener decision (it runs after boot, in the
 * background). */
static bool pl_wait_ready(const struct pl_node *node)
{
    const char *beta6 = node->private_listeners ? "not started: -private-listeners"
                                                : "serving beta6 bootstrap snapshots on";
    long deadline = pl_now_ms() + PL_BOOT_WAIT_MS;
    struct pl_socket sockets[PL_MAX_SOCKETS];
    while (pl_now_ms() < deadline) {
        int status;
        if (waitpid(node->pid, &status, WNOHANG) == node->pid) return false;
        size_t n = pl_listeners(node->pid, sockets, PL_MAX_SOCKETS);
        if (pl_find(sockets, n, node->ports.rpc) && pl_find(sockets, n, node->ports.p2p) &&
            pl_log_has(node, "[boot-stage] services_running -> ready") &&
            pl_log_has(node, beta6))
            return true;
        pl_sleep_ms(250);
    }
    return false;
}

/* Re-reads the sockets for `ms` after readiness: a listener that opens after
 * the RPC port, or after the last console line, still lands in the window. */
static size_t pl_settle(struct pl_node *node, long ms, struct pl_socket *out, size_t cap)
{
    long deadline = pl_now_ms() + ms;
    size_t n = pl_listeners(node->pid, out, cap);
    while (pl_now_ms() < deadline) {
        if (pl_public(out, n) > 0) node->public_seen++;
        pl_sleep_ms(100);
        n = pl_listeners(node->pid, out, cap);
    }
    if (pl_public(out, n) > 0) node->public_seen++;
    return n;
}

static bool pl_connects(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    bool ok = fd >= 0 && connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
    if (fd >= 0) close(fd);
    return ok;
}

/* One request with no credentials; returns the bytes read. */
static size_t pl_unauthenticated(uint16_t port, const char *request, char *out, size_t cap)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    size_t used = 0;
    struct timeval tv = {.tv_sec = 5};
    if (fd < 0) return 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0 &&
        write(fd, request, strlen(request)) == (ssize_t)strlen(request)) {
        ssize_t got;
        while (used + 1 < cap && (got = read(fd, out + used, cap - 1 - used)) > 0)
            used += (size_t)got;
    }
    out[used] = '\0';
    close(fd);
    return used;
}

static bool pl_binary_present(void)
{
    struct stat st;
    if (stat(PL_NODE_BIN, &st) == 0) return true;
    printf("FAIL private_listeners: %s is missing; run make z23 first\n", PL_NODE_BIN);
    return false;
}

static struct pl_node g_node;
static struct pl_socket g_sockets[PL_MAX_SOCKETS];
static size_t g_count;

PL_CASE(pl_node_private_loopback, "private_listeners: every socket of the running node is loopback, through boot and a settle window")
    ASSERT(pl_start(&g_node, true));
    bool ready = pl_wait_ready(&g_node);
    if (!ready) printf("(console log: %s) ", g_node.log);
    ASSERT(ready);
    g_count = pl_settle(&g_node, 4000, g_sockets, PL_MAX_SOCKETS);
    ASSERT(g_count >= 2);
    ASSERT_EQ(pl_public(g_sockets, g_count), (size_t)0);
    ASSERT_EQ(g_node.public_seen, 0);
    ASSERT(pl_find(g_sockets, g_count, g_node.ports.rpc) != NULL);
    ASSERT(pl_find(g_sockets, g_count, g_node.ports.p2p) != NULL);
    ASSERT(!pl_find(g_sockets, g_count, g_node.ports.p2p)->v6);
PL_END

PL_CASE(pl_node_private_absent, "private_listeners: no HTTPS, HTTP, file service, beta6 side or RPC TLS listener")
    ASSERT(pl_find(g_sockets, g_count, g_node.ports.https) == NULL);
    ASSERT(pl_find(g_sockets, g_count, g_node.ports.http) == NULL);
    ASSERT(pl_find(g_sockets, g_count, g_node.ports.fs) == NULL);
    ASSERT(pl_find(g_sockets, g_count, g_node.ports.tls) == NULL);
    ASSERT(pl_find(g_sockets, g_count, g_node.ports.beta6) == NULL);
    ASSERT(!pl_connects(g_node.ports.https));
    ASSERT(!pl_connects(g_node.ports.http));
    ASSERT(!pl_connects(g_node.ports.fs));
    ASSERT(!pl_connects(g_node.ports.beta6));
PL_END

PL_CASE(pl_node_private_reads, "private_listeners: an unauthenticated loopback client learns nothing about the wallet")
    static const char *const secrets[] = {"wallet_view_ready", "wallet_spend_allowed",
                                          "auto_reindex_marker_path", "/data", "#!/"};
    static const char *const requests[] = {
        "GET /api/v1/status HTTP/1.0\r\n\r\n",
        "GET / HTTP/1.0\r\n\r\n",
        "POST / HTTP/1.0\r\nContent-Length: 44\r\n\r\n"
        "{\"method\":\"getinfo\",\"params\":[],\"id\":1}\r\n",
    };
    char reply[4096];
    for (size_t r = 0; r < 3; r++) {
        (void)pl_unauthenticated(g_node.ports.rpc, requests[r], reply, sizeof(reply));
        ASSERT(strstr(reply, " 200 ") == NULL);
        for (size_t s = 0; s < 5; s++) ASSERT(strstr(reply, secrets[s]) == NULL);
    }
    (void)pl_unauthenticated(g_node.ports.rpc, requests[2], reply, sizeof(reply));
    ASSERT(strstr(reply, " 401 ") != NULL);
PL_END

PL_CASE(pl_node_private_nat, "private_listeners: the NAT probe stays off")
    ASSERT(pl_log_has(&g_node, "Reachability: probe off (-private-listeners)"));
PL_END

PL_CASE(pl_node_private_final, "private_listeners: the sockets read again after every probe are still loopback")
    g_count = pl_settle(&g_node, 1500, g_sockets, PL_MAX_SOCKETS);
    ASSERT_EQ(pl_public(g_sockets, g_count), (size_t)0);
    ASSERT_EQ(g_node.public_seen, 0);
PL_END

/* Polls until every port in `want` is open, so the control does not depend on
 * which service opens last. */
static bool pl_wait_ports(struct pl_node *node, const uint16_t *want, size_t count)
{
    long deadline = pl_now_ms() + 30000;
    for (;;) {
        g_count = pl_listeners(node->pid, g_sockets, PL_MAX_SOCKETS);
        bool all = true;
        for (size_t i = 0; i < count; i++) all = all && pl_find(g_sockets, g_count, want[i]);
        if (all) return true;
        if (pl_now_ms() > deadline) return false;
        pl_sleep_ms(250);
    }
}

PL_CASE(pl_node_public, "private_listeners: without the option the node keeps its public listeners")
    pl_stop(&g_node);
    ASSERT(pl_start(&g_node, false));
    bool ready = pl_wait_ready(&g_node);
    if (!ready) printf("(console log: %s) ", g_node.log);
    ASSERT(ready);
    const uint16_t want[] = {g_node.ports.p2p, g_node.ports.rpc, g_node.ports.https,
                             g_node.ports.http, g_node.ports.fs, g_node.ports.tls,
                             g_node.ports.beta6};
    ASSERT(pl_wait_ports(&g_node, want, 7));
    ASSERT(pl_loopback(pl_find(g_sockets, g_count, g_node.ports.rpc)));
    ASSERT(!pl_loopback(pl_find(g_sockets, g_count, g_node.ports.p2p)));
    ASSERT(!pl_loopback(pl_find(g_sockets, g_count, g_node.ports.https)));
    ASSERT(!pl_loopback(pl_find(g_sockets, g_count, g_node.ports.http)));
    ASSERT(!pl_loopback(pl_find(g_sockets, g_count, g_node.ports.fs)));
    ASSERT(!pl_loopback(pl_find(g_sockets, g_count, g_node.ports.tls)));
    ASSERT(!pl_loopback(pl_find(g_sockets, g_count, g_node.ports.beta6)));
    ASSERT(!pl_log_has(&g_node, "probe off (-private-listeners)"));
PL_END

static int test_private_listeners_node(void)
{
    if (!pl_binary_present()) return 1;
    int failures = pl_node_private_loopback() + pl_node_private_absent() +
                   pl_node_private_reads() + pl_node_private_nat() + pl_node_private_final() +
                   pl_node_public();
    pl_stop(&g_node);
    return failures;
}

#else

static int test_private_listeners_node(void)
{
    printf("UNOBSERVED (private_listeners: the process cases read /proc and need Linux)\n");
    return 0;
}

#endif

int test_private_listeners(void)
{
    return test_private_listeners_args() + test_private_listeners_node();
}
