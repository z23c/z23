/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mock_rpc — simulated zclassicd RPC server for end-to-end testing.
 *
 * Listens on a configurable port (default 18232 to avoid conflict),
 * responds to all RPC methods the wallet uses, with controllable
 * test state. Run alongside build/bin/zclassic23 on an isolated RPC port.
 * for full end-to-end testing with no real blockchain.
 *
 * Or: use as a library by calling mock_rpc_start() from test code.
 *
 * Supported RPC methods:
 *   z_gettotalbalance  — returns configurable t/z/total
 *   listunspent        — returns configurable UTXOs
 *   z_listunspent      — returns configurable shielded notes
 *   z_sendmany         — simulates shield/send (returns opid)
 *   z_getoperationstatus — returns success for known opids
 *   gettransaction     — returns configurable tx data
 *   z_listaddresses    — returns test z-addresses
 *   getinfo            — returns chain info */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* glibc spells the loopback constant for you; POSIX leaves it to the host
 * headers. One literal fallback keeps this tool header-only portable. */
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001u /* 127.0.0.1 */
#endif
#include <sys/time.h>
#include <signal.h>

/* ── Configurable test state ──────────────────────────── */

static struct {
    double transparent;     /* ZCL */
    double shielded;        /* ZCL */
    int block_height;
    int peers;
    int mempool;
    const char *t_address;
    const char *z_address;
    int opid_counter;
    volatile int running;
    int port;
} g_mock = {
    .transparent = 0.81491089,
    .shielded    = 0.16000000,
    .block_height = 3041000,
    .peers = 8,
    .mempool = 3,
    .t_address = "t1SiGuVYeQmp2cw7zQ2XgL8r3bkvhyymMoJ",
    .z_address = "zs19hc6ghlrzklr7y82u9w6822zuvrpfmgzlqz7alx8eqtwh2rvzgykl6m3lu8gwarpflcczgyse2p",
    .opid_counter = 0,
    .running = 1,
    .port = 18232,
};

/* ── RPC response builders ────────────────────────────── */

static int respond(int fd, const char *method, const char *params) {
    char result[8192];

    if (strcmp(method, "z_gettotalbalance") == 0) {
        snprintf(result, sizeof(result),
            "{\"result\":{\"transparent\":\"%.8f\","
            "\"private\":\"%.8f\","
            "\"total\":\"%.8f\"},"
            "\"error\":null,\"id\":1}",
            g_mock.transparent, g_mock.shielded,
            g_mock.transparent + g_mock.shielded);
    }
    else if (strcmp(method, "listunspent") == 0) {
        if (g_mock.transparent > 0.00001) {
            snprintf(result, sizeof(result),
                "{\"result\":[{\"txid\":\"aabb000000000000000000000000000000"
                "00000000000000000000000000ccdd\","
                "\"vout\":0,\"generated\":false,"
                "\"address\":\"%s\","
                "\"amount\":%.8f,"
                "\"confirmations\":100,\"spendable\":true}],"
                "\"error\":null,\"id\":1}",
                g_mock.t_address, g_mock.transparent);
        } else {
            snprintf(result, sizeof(result),
                "{\"result\":[],\"error\":null,\"id\":1}");
        }
    }
    else if (strcmp(method, "z_listunspent") == 0) {
        if (g_mock.shielded > 0.00001) {
            snprintf(result, sizeof(result),
                "{\"result\":[{\"txid\":\"eeff000000000000000000000000000000"
                "00000000000000000000000000aabb\","
                "\"outindex\":0,\"confirmations\":50,"
                "\"spendable\":true,"
                "\"address\":\"%s\","
                "\"amount\":%.8f,"
                "\"memo\":\"f600\",\"change\":false}],"
                "\"error\":null,\"id\":1}",
                g_mock.z_address, g_mock.shielded);
        } else {
            snprintf(result, sizeof(result),
                "{\"result\":[],\"error\":null,\"id\":1}");
        }
    }
    else if (strcmp(method, "z_sendmany") == 0) {
        g_mock.opid_counter++;
        snprintf(result, sizeof(result),
            "{\"result\":\"opid-mock-%04d\",\"error\":null,\"id\":1}",
            g_mock.opid_counter);
        /* Simulate the shield: move funds */
        if (strstr(params, g_mock.z_address)) {
            /* Shield operation: t → z */
            double move = g_mock.transparent - 0.0001;
            if (move > 0) {
                g_mock.shielded += move;
                g_mock.transparent = 0.00009459; /* dust */
            }
        }
        printf("  [mock] z_sendmany → opid-mock-%04d\n", g_mock.opid_counter);
    }
    else if (strcmp(method, "z_getoperationstatus") == 0) {
        snprintf(result, sizeof(result),
            "{\"result\":[{\"id\":\"opid-mock-%04d\","
            "\"status\":\"success\",\"creation_time\":1700000000,"
            "\"result\":{\"txid\":\"mockresulttxid000000000000000000"
            "00000000000000000000000000000000\"},"
            "\"method\":\"z_sendmany\"}],"
            "\"error\":null,\"id\":1}",
            g_mock.opid_counter);
    }
    else if (strcmp(method, "gettransaction") == 0) {
        snprintf(result, sizeof(result),
            "{\"result\":{\"confirmations\":100,"
            "\"txid\":\"mocktxid\",\"time\":1700000000},"
            "\"error\":null,\"id\":1}");
    }
    else if (strcmp(method, "getinfo") == 0) {
        snprintf(result, sizeof(result),
            "{\"result\":{\"blocks\":%d,\"connections\":%d,"
            "\"testnet\":false,\"version\":2001653},"
            "\"error\":null,\"id\":1}",
            g_mock.block_height, g_mock.peers);
    }
    else if (strcmp(method, "z_listaddresses") == 0) {
        snprintf(result, sizeof(result),
            "{\"result\":[\"%s\"],\"error\":null,\"id\":1}",
            g_mock.z_address);
    }
    else {
        /* Unknown method — return empty result */
        snprintf(result, sizeof(result),
            "{\"result\":null,\"error\":{\"code\":-32601,"
            "\"message\":\"Method not found: %s\"},"
            "\"id\":1}", method);
        printf("  [mock] unknown method: %s\n", method);
    }

    char http[16384];
    int hlen = snprintf(http, sizeof(http),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: engine/application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s",
        strlen(result), result);

    return (int)write(fd, http, (size_t)hlen);
}

/* ── Request handler ──────────────────────────────────── */

static void handle_client(int client_fd) {
    char req[8192] = "";
    ssize_t n = read(client_fd, req, sizeof(req) - 1);
    if (n <= 0) { close(client_fd); return; }
    req[n] = '\0';

    /* Find JSON body */
    const char *body = strstr(req, "\r\n\r\n");
    if (body) body += 4;
    else body = req;

    /* Extract method */
    char method[64] = "";
    const char *mp = strstr(body, "\"method\"");
    if (mp) {
        mp = strchr(mp + 8, '"');
        if (mp) {
            mp++;
            const char *me = strchr(mp, '"');
            if (me && (size_t)(me - mp) < sizeof(method)) {
                memcpy(method, mp, (size_t)(me - mp));
                method[me - mp] = '\0';
            }
        }
    }

    /* Extract params */
    const char *params = "[]";
    const char *pp = strstr(body, "\"params\"");
    if (pp) {
        pp += 8;
        while (*pp == ' ' || *pp == ':') pp++;
        params = pp;
    }

    respond(client_fd, method, params);
    close(client_fd);
}

/* ── Server thread ────────────────────────────────────── */

static void *server_thread(void *arg) {
    (void)arg;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return NULL; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons((uint16_t)g_mock.port),
    };

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(srv);
        return NULL;
    }
    listen(srv, 8);

    printf("[mock_rpc] listening on port %d\n", g_mock.port);
    printf("[mock_rpc] transparent=%.8f shielded=%.8f total=%.8f\n",
           g_mock.transparent, g_mock.shielded,
           g_mock.transparent + g_mock.shielded);

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (g_mock.running) {
        int client = accept(srv, NULL, NULL);
        if (client >= 0)
            handle_client(client);
    }

    close(srv);
    return NULL;
}

/* ── Public API ───────────────────────────────────────── */

pthread_t mock_rpc_start(int port, double transparent, double shielded) {
    g_mock.port = port;
    g_mock.transparent = transparent;
    g_mock.shielded = shielded;
    g_mock.running = 1;

    /* Write a fake cookie file so wv_rpc_call can auth */
    const char *home = getenv("HOME");
    if (home) {
        char path[512];
        snprintf(path, sizeof(path), "%s/.zclassic-c23/.cookie", home);
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "mockuser:mockpass\n");
            fclose(f);
        }
    }

    pthread_t t;
    /* raw-pthread-ok: test-tool (mock RPC server, not production) */
    pthread_create(&t, NULL, server_thread, NULL);
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };
    nanosleep(&ts, NULL); /* let server bind */
    return t;
}

void mock_rpc_stop(pthread_t t) {
    g_mock.running = 0;
    pthread_join(t, NULL);
}

/* ── Standalone mode ──────────────────────────────────── */

int main(int argc, char **argv) {
    double t_bal = 0.81491089, z_bal = 0.16000000;
    int port = 8232;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--port=", 7) == 0)
            port = atoi(argv[i] + 7);
        if (strncmp(argv[i], "--transparent=", 14) == 0)
            t_bal = strtod(argv[i] + 14, NULL);
        if (strncmp(argv[i], "--shielded=", 11) == 0)
            z_bal = strtod(argv[i] + 11, NULL);
    }

    signal(SIGINT, (void(*)(int))(void(*)(void))exit);

    printf("Z23 Mock RPC Server\n");
    printf("Port: %d  Transparent: %.8f  Shielded: %.8f\n\n",
           port, t_bal, z_bal);

    pthread_t t = mock_rpc_start(port, t_bal, z_bal);

    printf("Press Ctrl+C to stop.\n\n");
    printf("In another terminal:\n");
    printf("  build/bin/z23      (wallet connects to mock)\n");
    printf("  make check-wallet         (automated verification)\n\n");

    pthread_join(t, NULL);
    return 0;
}
