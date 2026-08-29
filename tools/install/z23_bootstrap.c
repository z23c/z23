/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the C23 install front door — everything the shell shim at
 * https://z23.sh used to do except detecting the machine, downloading this
 * program and checking its digest.
 *
 * WHY THIS PROGRAM EXISTS AT ALL.
 * `curl https://z23.sh | sh` executes every byte of the shim BEFORE anything
 * has been verified. The shim's own header admits it: "a compromised origin
 * can replace both this program and its checks." So every line of logic that
 * sits in the shim is a line an attacker rewrites for free, and shrinking the
 * shim shrinks the unverifiable surface. It went from 206 lines of POSIX sh
 * plus a hand-maintained 322-line PowerShell twin to ~30 lines each that do
 * four things: name the machine, fetch one bootstrap, check its SHA-256
 * against a baked-in hash, and run it. Past that point the bytes executing
 * are bytes whose digest was checked, and they are these.
 *
 * WHAT THIS STILL DOES NOT PROVE. The shim's baked digest is not an external
 * trust anchor for a shim fetched from the same origin; a compromised origin
 * replaces both. This program raises the bar from "trust the origin for 206
 * lines of policy" to "trust the origin for 30 lines and one hash". An
 * independently verified bootstrap must authenticate the shim against an
 * anchor obtained outside z23.sh. See docs/work/BOOTSTRAP_PLAN.md.
 *
 * THE JUDGEMENT ITSELF is in lib/install (pure, no I/O, unit-tested by
 * lib/test/src/test_z23_front_door.c). This file is the transports: uname,
 * a DNS datagram, two HTTPS GETs, a SHA-256, and the handoff. It is compiled
 * STRAIGHT FROM SOURCE to an executable with no intermediate object files,
 * for the same reason zclassic23-acme is: it links a TLS client and a CA
 * trust store, and lib/test/src/test_cold_join_sovereign.c P2 scans every Z23
 * object under the build obj epochs for exactly those symbols. Nothing compiled here
 * can appear in a scanned epoch tree, which keeps that assertion green
 * honestly rather than by exemption.
 */

#define _POSIX_C_SOURCE 200809L

#include "install/front_door.h"

#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "tls_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#define BOOTSTRAP_PATH_MAX 1024
#define REPO_PIN_MAX_BYTES 512
#define INSTALLER_MAX_BYTES (256u * 1024u)
#define REPO_PIN_TIMEOUT_MS 20000
#define INSTALLER_TIMEOUT_MS 60000
#define DNS_TIMEOUT_MS 5000
#define DNS_MAX_SERVERS 3
#define DNS_REPLY_MAX 1500

/* Channel 1 of 3: the pin baked into these bytes, rewritten by the release
 * cutter. The all-zero sentinel means NO RELEASE IS PINNED YET, and it counts
 * as a source that did not answer — never as a pin. */
static const char k_baked_pin[] =
    "z23-pin-v1:"
    "0000000000000000000000000000000000000000000000000000000000000000:"
    "0000000000000000000000000000000000000000000000000000000000000000";

static const char k_default_origin[] = "https://z23.sh";
static const char k_default_pin_dns[] = "_z23-pin.z23.sh";
static const char k_default_pin_repo[] =
    "https://raw.githubusercontent.com/ZclassiC23/zclassic/main/"
    "packaging/install/RELEASE_PIN";

/* The scratch directory, and the only two names we ever create inside it.
 * They are listed rather than scanned because the signal handler below has to
 * remove them with async-signal-safe calls only: unlink() and rmdir() are on
 * the POSIX safe list, opendir()/readdir() are not. */
static char g_work[BOOTSTRAP_PATH_MAX];
static const char *const k_work_files[] = { "repo.pin", "install_z23.sh" };

/* Set when any Z23_INSTALL_TEST_* URL override is present. It is the ONLY
 * thing that lets a file:// URL be fetched. Anyone who can set your
 * environment already owns this process — the same argument that lets the
 * baked-pin override exist — but the compiled-in defaults are https and
 * cannot name a local path, so a user who set nothing cannot reach it. */
static bool g_test_urls = false;

static void work_cleanup(void)
{
    if (g_work[0] == '\0')
        return;
    char path[BOOTSTRAP_PATH_MAX + 32];
    for (size_t i = 0; i < sizeof k_work_files / sizeof k_work_files[0]; i++) {
        (void)snprintf(path, sizeof path, "%s/%s", g_work, k_work_files[i]);
        (void)unlink(path);
    }
    (void)rmdir(g_work);
    g_work[0] = '\0';
}

static void on_signal(int sig)
{
    work_cleanup();
    /* The shim's traps mapped HUP/INT/TERM to 129/130/143; keep the same
     * exit codes so a wrapper that reads them still reads them. */
    _exit(sig == SIGHUP ? 129 : sig == SIGINT ? 130 : 143);
}

static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)fputs("z23-install: ", stderr);
    (void)vfprintf(stderr, fmt, ap);
    (void)fputc('\n', stderr);
    va_end(ap);
}

/* Every refusal names the thing it protects, never the shape of the caller:
 * no prompt and no terminal is required here, because this runs under a
 * coding agent as often as under a person. */
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)fputs("z23-install: REFUSE: ", stderr);
    (void)vfprintf(stderr, fmt, ap);
    (void)fputc('\n', stderr);
    va_end(ap);
    work_cleanup();
    exit(1);
}

static const char *env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

/* ── SHA-256 of a buffer, as lowercase hex ────────────────────────────────
 * lib/crypto owns the only SHA-256 in this tree; a second one here would be
 * a second thing to keep correct. */
static void sha256_hex(const unsigned char *data, size_t len,
                       char out[FD_HEX_LEN + 1])
{
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, digest);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0fu];
    }
    out[FD_HEX_LEN] = '\0';
}

/* ── Bounded fetch ────────────────────────────────────────────────────────
 * The cap is enforced on what is ever hashed, parsed or run. tls_client does
 * not follow redirects: a redirecting origin therefore reads as fetch-failed,
 * which is UNREACHABLE — the fail-safe direction — never as a disagreement. */
static bool fetch_bounded(const char *url, size_t max_bytes, int timeout_ms,
                          char **body, size_t *body_len)
{
    *body = NULL;
    *body_len = 0;

    if (strncmp(url, "file://", 7) == 0) {
        if (!g_test_urls)
            return false;
        const char *path = url + 7;
        FILE *f = fopen(path, "rb");
        if (!f)
            return false;
        char *buf = zcl_malloc(max_bytes + 1, "z23-bootstrap fetch");
        if (!buf) {
            (void)fclose(f);
            return false;
        }
        const size_t n = fread(buf, 1, max_bytes + 1, f);
        (void)fclose(f);
        if (n > max_bytes) {
            free(buf);
            return false;
        }
        buf[n] = '\0';
        *body = buf;
        *body_len = n;
        return true;
    }

    struct tls_client_request req = {
        .method = "GET",
        .url = url,
        .user_agent = "z23-bootstrap/1",
        .timeout_ms = timeout_ms,
    };
    struct tls_client_response resp;
    if (!tls_client_fetch(&req, &resp))
        return false;
    if (resp.status != 200 || resp.body_len > max_bytes) {
        tls_client_response_free(&resp);
        return false;
    }
    char *buf = zcl_malloc(resp.body_len + 1, "z23-bootstrap body");
    if (!buf) {
        tls_client_response_free(&resp);
        return false;
    }
    memcpy(buf, resp.body, resp.body_len);
    buf[resp.body_len] = '\0';
    *body = buf;
    *body_len = resp.body_len;
    tls_client_response_free(&resp);
    return true;
}

/* ── Source 2 of 3: the DNS TXT record ────────────────────────────────────
 * No DNS-over-HTTPS fallback: buying this source back by trusting an unnamed
 * third-party resolver is a worse dependency than the one it replaces.
 * Losing DNS costs one vote; the quorum rule decides the rest. */
static size_t read_nameservers(const char *path,
                               char servers[DNS_MAX_SERVERS][64])
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[512];
    size_t n = 0;
    while (n < DNS_MAX_SERVERS && fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (strncmp(p, "nameserver", 10) != 0)
            continue;
        p += 10;
        if (*p != ' ' && *p != '\t')
            continue;
        while (*p == ' ' || *p == '\t')
            p++;
        size_t len = strcspn(p, " \t\r\n#");
        if (len == 0 || len >= 64)
            continue;
        memcpy(servers[n], p, len);
        servers[n][len] = '\0';
        n++;
    }
    (void)fclose(f);
    return n;
}

/* One query to one server. Returns the reply length, or 0. */
static size_t dns_ask(const char *server, const unsigned char *query,
                      size_t query_len, unsigned char *reply, size_t reply_cap)
{
    struct sockaddr_storage sa;
    socklen_t sa_len;
    memset(&sa, 0, sizeof sa);

    struct sockaddr_in *v4 = (struct sockaddr_in *)&sa;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&sa;
    if (inet_pton(AF_INET, server, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(53);
        sa_len = sizeof *v4;
    } else if (inet_pton(AF_INET6, server, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(53);
        sa_len = sizeof *v6;
    } else {
        /* resolv.conf may only name addresses; a hostname there would need a
         * resolver to resolve the resolver. */
        return 0;
    }

    const int fd = socket(sa.ss_family, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    size_t got = 0;
    if (sendto(fd, query, query_len, 0, (struct sockaddr *)&sa, sa_len) ==
        (ssize_t)query_len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        const int ready = poll(&pfd, 1, DNS_TIMEOUT_MS);
        if (ready > 0) {
            const ssize_t n = recv(fd, reply, reply_cap, 0);
            if (n > 0)
                got = (size_t)n;
        }
    }
    (void)close(fd);
    return got;
}

/* The harness hook. A file of TXT character-strings, one per line, standing
 * in for a datagram — the shim's selftest mocked `dig` on PATH for the same
 * reason. The WIRE parser is not mocked here: it is fed hostile datagrams
 * byte by byte by lib/test/src/test_z23_front_door.c. */
static bool dns_txt_from_file(const char *path, struct fd_dns_txt *out,
                              const char **reason)
{
    memset(out, 0, sizeof *out);
    FILE *f = fopen(path, "r");
    if (!f) {
        *reason = "lookup-failed";
        return false;
    }
    char line[FD_DNS_STRING_MAX];
    while (out->count < FD_DNS_MAX_STRINGS && fgets(line, sizeof line, f)) {
        size_t n = strcspn(line, "\r\n");
        /* dig prints TXT strings quoted; accept them either way. */
        char *p = line;
        if (n >= 2 && p[0] == '"' && p[n - 1] == '"') {
            p++;
            n -= 2;
        }
        if (n == 0)
            continue;
        memcpy(out->s[out->count], p, n);
        out->s[out->count][n] = '\0';
        out->count++;
    }
    (void)fclose(f);
    if (out->count == 0) {
        *reason = "no-answer";
        return false;
    }
    return true;
}

static void dns_attestation(const char *name, struct fd_attestation *att)
{
    struct fd_dns_txt txt;
    const char *reason = "no-answer";

    const char *hook = getenv("Z23_INSTALL_TEST_DNS");
    if (hook && *hook) {
        if (!dns_txt_from_file(hook, &txt, &reason)) {
            fd_attestation_unreachable(att, "dns", reason);
            return;
        }
    } else {
        char servers[DNS_MAX_SERVERS][64];
        const char *conf = env_or("Z23_INSTALL_TEST_RESOLV_CONF",
                                  "/etc/resolv.conf");
        const size_t count = read_nameservers(conf, servers);
        if (count == 0) {
            /* The shell said `no-dns-tool` when dig, host and nslookup were
             * all absent from a minimal container. That cannot happen any
             * more — this program IS the DNS tool. What can still happen is a
             * container with no resolver configured at all. */
            fd_attestation_unreachable(att, "dns", "no-resolver");
            return;
        }
        unsigned char query[FD_DNS_QUERY_MAX];
        /* A per-run query ID. Not a security boundary — plain DNS has none —
         * but a fixed ID would let a stale datagram from a previous run be
         * accepted as this run's answer. */
        struct timespec now;
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        const uint16_t id = (uint16_t)((now.tv_nsec ^ (long)getpid()) & 0xffff);
        const size_t query_len = fd_dns_txt_query(id, name, query,
                                                  sizeof query);
        if (query_len == 0) {
            fd_attestation_unreachable(att, "dns", "bad-query-name");
            return;
        }
        bool got = false;
        reason = "lookup-failed";
        for (size_t i = 0; i < count && !got; i++) {
            unsigned char reply[DNS_REPLY_MAX];
            const size_t n = dns_ask(servers[i], query, query_len, reply,
                                     sizeof reply);
            if (n == 0)
                continue;
            switch (fd_dns_txt_parse(reply, n, id, &txt)) {
                case FD_DNS_OK:        got = true; break;
                case FD_DNS_NO_ANSWER: reason = "no-answer"; break;
                case FD_DNS_TRUNCATED: reason = "truncated-answer"; break;
                case FD_DNS_MALFORMED: reason = "malformed-answer"; break;
            }
        }
        if (!got) {
            fd_attestation_unreachable(att, "dns", reason);
            return;
        }
    }

    /* A captive portal or a hijacked resolver answers with something that is
     * not a pin at all. That is UNREACHABLE, not disagreement — it must not
     * trip our loudest refusal. */
    for (size_t i = 0; i < txt.count; i++) {
        struct fd_pin pin;
        if (fd_pin_parse(txt.s[i], &pin)) {
            fd_attestation_answered(att, "dns", &pin);
            return;
        }
    }
    fd_attestation_unreachable(att, "dns", "malformed-answer");
}

/* ── Source 3 of 3: the source repository ─────────────────────────────── */
static void repo_attestation(const char *url, struct fd_attestation *att)
{
    char *body = NULL;
    size_t body_len = 0;
    if (!fetch_bounded(url, REPO_PIN_MAX_BYTES, REPO_PIN_TIMEOUT_MS, &body,
                       &body_len)) {
        fd_attestation_unreachable(att, "repo", "fetch-failed");
        return;
    }
    struct fd_pin pin;
    /* An HTML error page, and the unset sentinel a repository carries before
     * the first release is cut, are both "nothing is pinned here" — not a
     * dissenting pin. */
    const bool ok = fd_pin_from_lines(body, &pin);
    free(body);
    if (ok)
        fd_attestation_answered(att, "repo", &pin);
    else
        fd_attestation_unreachable(att, "repo", "malformed-answer");
}

/* ── The machine ─────────────────────────────────────────────────────── */
static void detect_platform(char triple[FD_TRIPLE_MAX])
{
    struct utsname u;
    const char *sysname = "unknown";
    const char *machine = "unknown";
    if (uname(&u) == 0) {
        sysname = u.sysname;
        machine = u.machine;
    }
    /* Harness hooks, not install knobs: the shim's selftest put a fake
     * `uname` on PATH to prove the unpublished-platform refusal, and that
     * trick does not reach uname(2). */
    sysname = env_or("Z23_INSTALL_TEST_UNAME_S", sysname);
    machine = env_or("Z23_INSTALL_TEST_UNAME_M", machine);
    fd_platform_triple(sysname, machine, triple);
}

static bool have_on_path(const char *name)
{
    const char *path = getenv("PATH");
    if (!path || !*path)
        path = "/usr/bin:/bin";
    while (*path) {
        const size_t n = strcspn(path, ":");
        char candidate[BOOTSTRAP_PATH_MAX];
        if (n > 0 && n + strlen(name) + 2 < sizeof candidate) {
            memcpy(candidate, path, n);
            candidate[n] = '/';
            memcpy(candidate + n + 1, name, strlen(name) + 1);
            if (access(candidate, X_OK) == 0)
                return true;
        }
        path += n;
        if (*path == ':')
            path++;
    }
    return false;
}

int main(int argc, char **argv)
{
    bool print_pin = false;
    /* The shim forwards argv verbatim, so this is the same one-argument
     * surface install.sh had. An unknown argument is refused rather than
     * ignored: a typo that silently installs is worse than one that stops. */
    if (argc > 2)
        die("unknown argument: %s", argv[2]);
    if (argc == 2) {
        if (strcmp(argv[1], "--print-pin") == 0)
            print_pin = true;
        else
            die("unknown argument: %s", argv[1]);
    }

    const char *origin = getenv("Z23_INSTALL_TEST_ORIGIN");
    const char *repo_url = getenv("Z23_INSTALL_TEST_PIN_REPO_URL");
    g_test_urls = (origin && *origin) || (repo_url && *repo_url);
    if (!origin || !*origin)
        origin = k_default_origin;
    if (!repo_url || !*repo_url)
        repo_url = k_default_pin_repo;
    const char *pin_dns = env_or("Z23_INSTALL_TEST_PIN_DNS", k_default_pin_dns);

    char triple[FD_TRIPLE_MAX];
    detect_platform(triple);
    if (!print_pin) {
        if (!fd_platform_published(triple)) {
            die("no Z23 runtime is published for %s; published: %s", triple,
                fd_platform_published_list());
        }
        if (!have_on_path("bash"))
            die("the Z23 installer is a bash script and bash was not found");
    }

    /* Scratch space is created only once every refusal that can be made
     * without a network has been made — an unpublished platform must leave no
     * trace at all. */
    char template[BOOTSTRAP_PATH_MAX];
    const char *tmpdir = env_or("TMPDIR", "/tmp");
    if ((size_t)snprintf(template, sizeof template, "%s/z23-install.XXXXXX",
                         tmpdir) >= sizeof template)
        die("TMPDIR path is too long");
    if (!mkdtemp(template))
        die("could not create a scratch directory under %s", tmpdir);
    (void)snprintf(g_work, sizeof g_work, "%s", template);
    (void)signal(SIGHUP, on_signal);
    (void)signal(SIGINT, on_signal);
    (void)signal(SIGTERM, on_signal);

    struct fd_attestation att[3];
    /* Channel 1: baked into these bytes. Not an external trust anchor for a
     * copy of this program fetched from the same origin. */
    const char *baked = env_or("Z23_INSTALL_TEST_BAKED_PIN", k_baked_pin);
    struct fd_pin baked_pin;
    if (fd_pin_is_sentinel(baked))
        fd_attestation_unreachable(&att[0], "baked", "no-release-pinned");
    else if (fd_pin_parse(baked, &baked_pin))
        fd_attestation_answered(&att[0], "baked", &baked_pin);
    else
        fd_attestation_unreachable(&att[0], "baked", "malformed-answer");

    dns_attestation(pin_dns, &att[1]);
    repo_attestation(repo_url, &att[2]);

    struct fd_agreement agreement;
    fd_agree(att, 3, &agreement);
    switch (agreement.verdict) {
        case FD_VERDICT_DISAGREE:
            say("attested pin %s=%s", agreement.first_origin,
                agreement.first_pin);
            say("attested pin %s=%s", agreement.other_origin,
                agreement.other_pin);
            die("release pin disagreement between %s and %s — refusing to "
                "install either", agreement.first_origin,
                agreement.other_origin);
            break;
        case FD_VERDICT_NO_QUORUM:
            die("release pin quorum: %zu of %zu sources answered, two "
                "independent sources are required for pin consistency; this "
                "does not authenticate the first-stage script (unreachable: "
                "%s)", agreement.answered, agreement.total,
                agreement.unreachable[0] ? agreement.unreachable : "none");
            break;
        case FD_VERDICT_AGREED:
            break;
    }
    if (agreement.answered < agreement.total)
        say("release pin agreed by %zu of %zu sources (unreachable: %s)",
            agreement.answered, agreement.total, agreement.unreachable);

    if (print_pin) {
        (void)printf("%s\n", agreement.agreed.text);
        work_cleanup();
        return 0;
    }

    char installer_url[TLS_CLIENT_MAX_PATH];
    if ((size_t)snprintf(installer_url, sizeof installer_url,
                         "%s/install_z23.sh", origin) >= sizeof installer_url)
        die("the install origin URL is too long");
    char *installer = NULL;
    size_t installer_len = 0;
    if (!fetch_bounded(installer_url, INSTALLER_MAX_BYTES,
                       INSTALLER_TIMEOUT_MS, &installer, &installer_len))
        die("could not fetch %s", installer_url);

    char got[FD_HEX_LEN + 1];
    sha256_hex((const unsigned char *)installer, installer_len, got);
    if (strcmp(got, agreement.agreed.installer) != 0) {
        free(installer);
        die("installer digest mismatch — %s served bytes the agreed release "
            "pin does not name", origin);
    }

    char installer_path[BOOTSTRAP_PATH_MAX + 32];
    (void)snprintf(installer_path, sizeof installer_path, "%s/install_z23.sh",
                   g_work);
    const int fd = open(installer_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        free(installer);
        die("could not write the verified installer to %s", installer_path);
    }
    const ssize_t wrote = write(fd, installer, installer_len);
    (void)close(fd);
    free(installer);
    if (wrote != (ssize_t)installer_len)
        die("could not write the verified installer to %s", installer_path);

    /* The handoff. Every attestation goes through so the installer judges the
     * same evidence itself rather than taking our word for it. The current
     * convenience default is the same domain: an operator may select any
     * mirror with Z23_RELEASE_SOURCE, but automatic decentralized discovery
     * and failover do not exist yet. */
    char source[TLS_CLIENT_MAX_PATH + 32];
    const char *release_source = getenv("Z23_RELEASE_SOURCE");
    if (release_source && *release_source)
        (void)snprintf(source, sizeof source, "--source=%s", release_source);
    else
        (void)snprintf(source, sizeof source, "--source=%s/release/%s", origin,
                       triple);
    char manifest[FD_HEX_LEN + 32];
    (void)snprintf(manifest, sizeof manifest, "--manifest-sha256=%s",
                   agreement.agreed.manifest);
    char attest[3][FD_ATTEST_ARG_MAX];
    for (size_t i = 0; i < 3; i++) {
        if (!fd_attest_arg(&att[i], attest[i], sizeof attest[i]))
            die("could not render the %s attestation for the installer",
                att[i].origin);
    }
    char *child_argv[] = { (char *)"bash", installer_path, source, manifest,
                           attest[0], attest[1], attest[2], NULL };

    const pid_t pid = fork();
    if (pid < 0)
        die("could not start the verified installer");
    if (pid == 0) {
        execvp("bash", child_argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            die("lost track of the verified installer");
    }
    work_cleanup();
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}
