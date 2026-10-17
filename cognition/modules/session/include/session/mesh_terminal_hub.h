/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the terminal hub — a confined shell served over ONE byte stream
 * (a loopback TCP connection that the PSK device-host tunnel carries, or a
 * socket pair in tests). There is no Noise session, no ZID delegation and
 * no pairing record on this path: the post-quantum PSK tunnel is the
 * authenticity and confidentiality layer, and the 32-byte terminal key proves
 * that the peer on the loopback socket is the lead and not another local
 * process. The frames carry NO signed evidence; the exit status rides an
 * unsigned EXIT frame and is exactly as trustworthy as the tunnel.
 *
 * Wire (all integers big-endian). Every frame is a 3-byte header
 * [type u8][payload_len u16] and a payload of at most 3072 bytes, so an
 * interactive write costs one header and no copy: callers read keystrokes
 * and pty output directly into frame_buf + 3.
 *   S->C CHALLENGE 0x01  version u8 (=1), nonce[32]
 *   C->S HELLO     0x02  cols u16, rows u16, flags u8, name_len u8, name, argc u8,
 *                        argc x (len u16, bytes), mac[32]
 *                        mac = SHA3-256(domain || key || nonce ||
 *                              every byte above, in order)
 *   S->C READY     0x03  empty: the peer is admitted and the shell runs
 *   S->C REFUSE    0x04  code u8 (enum mesh_terminal_hub_refusal); closes
 *   both DATA      0x10  raw terminal bytes
 *   C->S RESIZE    0x11  cols u16, rows u16
 *   C->S CLOSE     0x12  reason u8 (the requester asks to end)
 *   S->C EXIT      0x13  reason u8, flags u8 (1 = exit_code valid,
 *                        2 = signal valid), exit_code u8, signal u8
 * The hello name is a label the client chooses. It is NOT verified; the
 * server audit line says so. */

#ifndef ZCL_SESSION_MESH_TERMINAL_HUB_H
#define ZCL_SESSION_MESH_TERMINAL_HUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "session/mesh_terminal_proto.h"

#define MESH_TERMINAL_HUB_VERSION 1u
#define MESH_TERMINAL_HUB_HEADER_BYTES 3u
#define MESH_TERMINAL_HUB_PAYLOAD_MAX MESH_TERMINAL_DATA_PAYLOAD_MAX
#define MESH_TERMINAL_HUB_FRAME_MAX \
    (MESH_TERMINAL_HUB_HEADER_BYTES + MESH_TERMINAL_HUB_PAYLOAD_MAX)
#define MESH_TERMINAL_HUB_KEY_BYTES 32u
#define MESH_TERMINAL_HUB_NONCE_BYTES 32u
#define MESH_TERMINAL_HUB_MAC_BYTES 32u
#define MESH_TERMINAL_HUB_NAME_MAX 32u
#define MESH_TERMINAL_HUB_ARGV_MAX 16u
#define MESH_TERMINAL_HUB_ARGV_BYTES 2000u
#define MESH_TERMINAL_HUB_EXEC_LABEL_MAX 256u
#define MESH_TERMINAL_HUB_FINGERPRINT_HEX 16u
#define MESH_TERMINAL_HUB_HANDSHAKE_MS 2000
#define MESH_TERMINAL_HUB_DEFAULT_ACTIVE 4u
#define MESH_TERMINAL_HUB_ACTIVE_MAX 16u

enum mesh_terminal_hub_frame {
    MESH_TERMINAL_HUB_CHALLENGE = 0x01,
    MESH_TERMINAL_HUB_HELLO = 0x02,
    MESH_TERMINAL_HUB_READY = 0x03,
    MESH_TERMINAL_HUB_REFUSE = 0x04,
    MESH_TERMINAL_HUB_DATA = 0x10,
    MESH_TERMINAL_HUB_RESIZE = 0x11,
    MESH_TERMINAL_HUB_CLOSE = 0x12,
    MESH_TERMINAL_HUB_EXIT = 0x13
};

enum mesh_terminal_hub_refusal {
    MESH_TERMINAL_HUB_REFUSE_AUTH = 1,
    MESH_TERMINAL_HUB_REFUSE_BUSY = 2,
    MESH_TERMINAL_HUB_REFUSE_REQUEST = 3,
    MESH_TERMINAL_HUB_REFUSE_CONFINEMENT = 4,
    MESH_TERMINAL_HUB_REFUSE_SHUTDOWN = 5,
    MESH_TERMINAL_HUB_REFUSE_EXEC = 6 /* the requested program cannot run */
};

#define MESH_TERMINAL_HUB_EXIT_HAS_CODE 1u
#define MESH_TERMINAL_HUB_EXIT_HAS_SIGNAL 2u

/* Fills the 3-byte header in front of a payload of `len` bytes (already in
 * frame + 3) and returns the whole frame size, or 0 when len is too large. */
size_t mesh_terminal_hub_frame_seal(uint8_t *frame, uint8_t type, size_t len);

/* Decodes a header. false when fewer than 3 bytes, an unknown type, or a
 * length past the payload maximum — the caller then drops the connection. */
bool mesh_terminal_hub_frame_header(const uint8_t *bytes, size_t have,
                                    uint8_t *type, size_t *payload_len);

/* What a HELLO says. flags: QUIET asks the server to turn the remote pty's
 * echo off (a piped, non-tty client has no use for a second copy of what it
 * sent). argv NULL runs the server's configured shell; otherwise the program
 * in argv[0] (an absolute path) runs inside the same cage. */
#define MESH_TERMINAL_HUB_HELLO_QUIET 1u

struct mesh_terminal_hub_request {
    uint16_t cols;
    uint16_t rows;
    uint8_t flags;
    const char *name;
    const char *const *argv; /* NULL-terminated, <= MESH_TERMINAL_HUB_ARGV_MAX */
};

/* HELLO payload: cols, rows, flags, name (sanitised to [A-Za-z0-9._-], cut
 * at the maximum), argv, then the mac for `nonce`. Returns the payload length,
 * or 0 when argv is too many strings or too many bytes. */
size_t mesh_terminal_hub_hello_build(
    uint8_t *payload, const uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
    const uint8_t nonce[MESH_TERMINAL_HUB_NONCE_BYTES],
    const struct mesh_terminal_hub_request *request);

struct mesh_terminal_hub_hello {
    uint16_t cols;
    uint16_t rows;
    uint8_t flags;
    char name[MESH_TERMINAL_HUB_NAME_MAX + 1]; /* sanitised, NUL ended */
    unsigned argc;                              /* 0: the server's shell */
    const char *argv[MESH_TERMINAL_HUB_ARGV_MAX + 1]; /* into argv_buf */
    char argv_buf[MESH_TERMINAL_HUB_ARGV_BYTES + MESH_TERMINAL_HUB_ARGV_MAX];
};

/* Escaped one-line rendering of an argv for the audit line: arguments joined
 * by a space, bytes outside printable ASCII plus space, '"' and '\\' as \xNN,
 * cut at MESH_TERMINAL_HUB_EXEC_LABEL_MAX bytes with "..." appended. */
void mesh_terminal_hub_exec_label(char *out, size_t cap, const char *const *argv,
                                  unsigned argc);
enum mesh_terminal_hub_hello_status {
    MESH_TERMINAL_HUB_HELLO_OK = 0,
    MESH_TERMINAL_HUB_HELLO_MALFORMED,
    MESH_TERMINAL_HUB_HELLO_GEOMETRY,
    MESH_TERMINAL_HUB_HELLO_MAC
};

/* Checks shape, geometry, then the mac in constant time. */
enum mesh_terminal_hub_hello_status mesh_terminal_hub_hello_verify(
    struct mesh_terminal_hub_hello *out, const uint8_t *payload, size_t len,
    const uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
    const uint8_t nonce[MESH_TERMINAL_HUB_NONCE_BYTES]);

/* Key file discipline. load: a regular file (never a symlink), owned by the
 * effective uid, mode exactly 0600, exactly 32 bytes. init: creates it
 * exclusively with mode 0600 from the OS CSPRNG, never overwrites, and
 * returns only the fingerprint (16 hex chars of SHA3-256 over the key under
 * a domain tag) — the key is never returned or printed. Both return false
 * with errno-free reason text in `why` (at least 96 bytes). */
bool mesh_terminal_hub_key_load(const char *path,
                                uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
                                char *why, size_t why_cap);
bool mesh_terminal_hub_key_init(const char *path,
                                char fingerprint[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1],
                                char *why, size_t why_cap);
void mesh_terminal_hub_key_fingerprint(
    const uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES],
    char out[MESH_TERMINAL_HUB_FINGERPRINT_HEX + 1]);

/* ── Server ───────────────────────────────────────────────────────────── */

struct mesh_terminal_hub_serve_cfg {
    uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES];
    const char *shell_path;  /* the ONE granted binary */
    const char *workdir;     /* the shared granted directory */
    uint64_t max_bytes_in;
    uint64_t max_bytes_out;
    uint64_t lifetime_seconds;
    uint64_t idle_seconds;
    int handshake_ms;        /* 0: MESH_TERMINAL_HUB_HANDSHAKE_MS */
    int stop_fd;             /* readable = end now with SHUTDOWN; -1 none */
    /* The supervisor's view of the worker group: set to the group id once the
     * shell is up, zeroed after the group is killed and before its leader is
     * reaped, so non-zero always names a group whose leader still holds the
     * id. NULL when nobody supervises. */
    volatile pid_t *worker_pgid;
};

struct mesh_terminal_hub_report {
    bool admitted;           /* the hello verified and the shell started */
    int refusal;             /* enum mesh_terminal_hub_refusal, 0 if none */
    int64_t start_unix;
    int64_t end_unix;
    uint64_t bytes_in;
    uint64_t bytes_out;
    enum mesh_terminal_close_reason reason;
    int exit_code;           /* -1 when the shell has none */
    int signal;              /* 0 when none */
    char name[MESH_TERMINAL_HUB_NAME_MAX + 1];
    char exec[MESH_TERMINAL_HUB_EXEC_LABEL_MAX + 8]; /* escaped argv, "-" for the shell */
};

/* Runs one session on a connected stream socket to its end. Blocks on poll
 * only: no sleeps, no polling loops; a timeout fires only at a real deadline
 * (handshake, lifetime, idle). Does not close fd. */
void mesh_terminal_hub_serve_fd(int fd,
                                const struct mesh_terminal_hub_serve_cfg *cfg,
                                struct mesh_terminal_hub_report *report);

/* Binds 127.0.0.1:port (0 = ephemeral), TCP_NODELAY inherited by accepts.
 * Returns the listening fd (or -1) and the bound port. */
int mesh_terminal_hub_listen(uint16_t port, uint16_t *bound_port);

struct mesh_terminal_hub_listen_cfg {
    struct mesh_terminal_hub_serve_cfg serve;
    unsigned max_active;     /* concurrent sessions, pre-auth included */
    unsigned max_sessions;   /* connection-attempt limit: stop after this many accepted
                              * connections, authenticated or not; 0 = run until signal */
    int audit_fd;            /* one line per session, O_APPEND or stderr */
    int audit_wait_ms;       /* longest a session waits for audit_fd to take its line,
                              * then the line is dropped and counted; 0 = 2000 */
    int stop_grace_ms;       /* after SIGTERM, how long sessions get to end before
                              * they are killed; 0 = 5000 */
};

/* Accepts on `listener` (closed on return), one forked child per session so
 * a crash or a wedge in one session cannot touch another. Returns 0 on a
 * clean stop (max_sessions reached or SIGTERM/SIGINT), non-zero on error.
 * MESH_TERMINAL_HUB_LISTEN_SINK_UNBOUNDED: off Linux, audit_fd is a blocking
 * pipe the hub would have to set O_NONBLOCK on to bound its writes, which it
 * never does to a shared descriptor; nothing is written to it. */
#define MESH_TERMINAL_HUB_LISTEN_SINK_UNBOUNDED 2
int mesh_terminal_hub_listen_run(int listener,
                                 const struct mesh_terminal_hub_listen_cfg *cfg);

#if defined(ZCL_TESTING)
/* Test seam: session children ignore SIGTERM (a wedged session). */
void mesh_terminal_hub_testing_children_ignore_term(bool ignore);
/* Test seam: called right before every hub write attempt (audit and client
 * output), so a test can make another writer win the race. NULL clears. */
void mesh_terminal_hub_testing_before_write(void (*hook)(int fd));
/* Test seam: the instant between "the descriptor looked ready" and the write
 * syscall (the polled and non-blocking pipe paths), where a second writer
 * takes the room. NULL clears. */
void mesh_terminal_hub_testing_after_ready(void (*hook)(int fd));
/* Test seam: make Linux treat a pipe as the non-Linux path does (no
 * RWF_NOWAIT: bounded only on an already non-blocking descriptor). */
void mesh_terminal_hub_testing_force_polled_fifo(bool on);
/* Test seam: called in the supervisor right after the stop grace expired and
 * before the survivors are frozen; kids[0..n) are the session pids (0 = free
 * slot), so a test can end a session from outside at that exact point. */
void mesh_terminal_hub_testing_before_freeze(void (*hook)(const pid_t *kids, unsigned n));
#endif

/* Formats the audit line for a finished session (without a trailing
 * newline); returns its length. */
size_t mesh_terminal_hub_audit_line(
    char *out, size_t cap, const struct mesh_terminal_hub_report *report);

/* ── Client ───────────────────────────────────────────────────────────── */

struct mesh_terminal_hub_client_cfg {
    uint8_t key[MESH_TERMINAL_HUB_KEY_BYTES];
    const char *name;
    const char *const *argv; /* NULL: the server's shell */
    bool quiet;       /* non-tty client: ask for the remote echo to be off */
    int net_fd;       /* the stream to the server */
    int in_fd;        /* keystrokes in */
    int out_fd;       /* screen out */
    int event_fd;     /* 'W' = window changed, 'S' = stop; -1 none */
    int handshake_ms; /* 0: 20000 (a tunnel handshake included) */
    bool (*window)(void *ctx, uint16_t *cols, uint16_t *rows);
    void *window_ctx;
};

struct mesh_terminal_hub_client_result {
    int exit_code;        /* the process exit code */
    char code[24];        /* typed code for the one error line, "" if none */
    char message[160];    /* human line, "" if none */
    unsigned output_dropped; /* closing newline dropped at its deadline (a wedged reader) */
};

/* Drives one session to its end. Exit code: the remote shell's own (or
 * 128+signal); 2 invalid, 3 blocked (no confinement), 4 denied (key
 * refused), 5 transient (busy, lost, limits, no answer), 6 internal,
 * 130 interrupted. */
void mesh_terminal_hub_client_run(
    const struct mesh_terminal_hub_client_cfg *cfg,
    struct mesh_terminal_hub_client_result *result);

#endif /* ZCL_SESSION_MESH_TERMINAL_HUB_H */
