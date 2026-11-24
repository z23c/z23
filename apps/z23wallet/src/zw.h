/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the single internal header of the z23-wallet GUI program. */
#ifndef ZW_H
#define ZW_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "gui/ui.h"
#include "gui/window.h"
#include "json/json.h"

#define ZW_PATH 512
#define ZW_MAX_MONEY INT64_C(2100000000000000) /* 21e6 ZCL in zatoshi */
#define ZW_VERSION "0.2"
#define ZW_RELEASE_DATE "Nov 23 2026"
#define ZW_CRED_MAX 1024 /* rpcuser / rpcpassword bytes accepted from zclassic.conf */

enum zw_err {
    ZW_OK = 0, ZW_ERR_REFUSED, ZW_ERR_TIMEOUT, ZW_ERR_AUTH, ZW_ERR_BAD_REPLY,
    ZW_ERR_RPC, ZW_ERR_NOMEM, ZW_ERR_IO, ZW_ERR_SEARCHING
};

enum zw_profile { ZW_PROFILE_AUTO, ZW_PROFILE_Z23, ZW_PROFILE_ZCLASSICD };

struct zw_options {
    char datadir[ZW_PATH];
    uint16_t rpcport;
    enum zw_profile profile;
    enum gui_backend_kind backend;
    int32_t width, height;
    float scale;
    char script[ZW_PATH], shot[ZW_PATH], shot_dir[ZW_PATH], bench[ZW_PATH],
        log[ZW_PATH], z23[ZW_PATH];
    int32_t shot_after_ms, qa_frames;
    bool exit_after_shot, version, help;
};

/* ---- log ---- */
void zw_log_open(const char *path);
void zw_log_close(void);
void zw_log_secret(const char *secret); /* any line containing it is dropped */
void zw_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* ---- args ---- */
bool zw_args_parse(int argc, char **argv, struct zw_options *o, char *err, size_t cap);
const char *zw_args_help(void);

/* ---- amounts (integer zatoshi) ---- */
bool zw_amount_parse(const char *s, size_t len, int64_t *zat);
bool zw_amount_from_json(const struct json_value *v, int64_t *zat);
/* Legacy display format: up to 8 decimals, trailing zeros stripped, no
 * thousands separators; unit appends " ZCL" (" ZCT" when testnet). */
size_t zw_amount_format(int64_t zat, char *buf, size_t cap, bool unit);
size_t zw_amount_format_net(int64_t zat, char *buf, size_t cap, bool testnet);
void zw_fmt_int(int64_t v, char *buf, size_t cap); /* heights: 1,234,567 */
void zw_fmt_age(int64_t seconds, char *buf, size_t cap); /* "16 s", "3 min", "2 h", "5 days" */

/* ---- locate ---- */
FILE *zw_fopen_read(const char *path_utf8);
FILE *zw_fopen_append_private(const char *path_utf8);
enum zw_cred { ZW_CRED_NONE, ZW_CRED_COOKIE, ZW_CRED_CONF };
struct zw_endpoint {
    char host[16];
    uint16_t port;
    char datadir[ZW_PATH];    /* the node's data folder */
    char cookie_dir[ZW_PATH]; /* where .cookie lives (datadir=, testnet3/, regtest/) */
    char conf_path[ZW_PATH];  /* zclassic.conf that supplied credentials, if any */
    char auth[2800]; /* full "Authorization" header value; cleansed on replace */
    enum zw_profile profile;
    enum zw_cred cred_src;
    bool testnet, regtest, valid;
};
#define ZW_TRIED_MAX 10
struct zw_tried { char path[ZW_PATH]; char reason[48]; };
struct zw_locate_report {
    struct zw_tried tried[ZW_TRIED_MAX];
    size_t ntried;
};
bool zw_locate(const struct zw_options *o, struct zw_endpoint *ep, struct zw_locate_report *rep);
bool zw_cookie_load(struct zw_endpoint *ep);
void zw_endpoint_wipe(struct zw_endpoint *ep);
bool zw_base64(const unsigned char *in, size_t n, char *out, size_t cap);

/* ---- http / rpc ---- */
/* Aborts requests from another thread: fire is permanent (shutdown), abort ends
 * only the request in flight and is cleared before the next job (watchdog). */
struct zw_cancel;
struct zw_cancel *zw_cancel_new(void);
void zw_cancel_free(struct zw_cancel *c);
void zw_cancel_fire(struct zw_cancel *c);
void zw_cancel_abort(struct zw_cancel *c);
void zw_cancel_clear_abort(struct zw_cancel *c);
enum zw_phase { ZW_PHASE_IDLE, ZW_PHASE_LOCATE, ZW_PHASE_CONNECT, ZW_PHASE_SEND, ZW_PHASE_RECV };
const char *zw_phase_name(int phase);
struct zw_buf { char *data; size_t len, cap; };
void zw_buf_free(struct zw_buf *b);
/* One request; deadline_ms bounds connect + send + every receive together. */
enum zw_err zw_http_post(const struct zw_endpoint *ep, const char *body, size_t len,
                         struct zw_buf *reply, uint32_t deadline_ms, int *http_status,
                         atomic_int *phase, struct zw_cancel *cancel);

struct zw_rpc_error { int code; enum zw_err kind; char message[160]; };
struct zw_rpc {
    struct zw_endpoint ep;
    const struct zw_options *opt;
    struct zw_cancel *cancel; /* may be NULL */
    struct zw_locate_report report;
    bool missing_walletsummary, missing_getwalletsummary, z23_refused;
    bool may_send; /* only the Send runner's client may call z_sendmany */
    uint32_t next_id;
    uint32_t deadline_ms; /* 0 = 5000 */
    atomic_int phase;
    atomic_llong progress_ms; /* monotonic ms of the last finished node call (the watchdog measures from it) */
};
/* Against zclassicd only the allowlisted calls are sent (R5): the reads and
 * the Send page's z_sendmany and its status reads. */
bool zw_rpc_legacy_allowed(const char *method);
/* Locate the node now if needed; false when none was found. */
bool zw_rpc_ensure(struct zw_rpc *r);
/* REFUSED, or a TIMEOUT while connecting: nothing listens on the port. */
bool zw_rpc_unreachable(enum zw_err err, int fail_phase);
/* Stamp progress: one node call (or locate) finished, whatever its outcome. */
void zw_rpc_progress(struct zw_rpc *r);
enum zw_err zw_rpc_call(struct zw_rpc *r, const char *method, const char *params_json,
                        struct json_value *result, struct zw_rpc_error *e);

/* ---- queries, worker, model ---- */
enum zw_query { ZW_Q_CHAIN, ZW_Q_NET, ZW_Q_WALLET, ZW_Q_BALANCES, ZW_Q_INFO, ZW_Q_COUNT };

struct zw_chain {
    int64_t blocks, headers, tiptime;
    int32_t progress_permille;
    char chain[16];
    bool provisional, ibd;
};
struct zw_net { int64_t connections, inbound, outbound, version; char subversion[64]; };
struct zw_info { int64_t connections, version, solps; bool has_solps; };
struct zw_wallet {
    int64_t spendable, pending, publicf, immature, total, scanned, behind;
    bool send_allowed, current, locked, encrypted, known, legacy;
    char reason[112];
};

#define ZW_BAL_MAX 512
enum zw_addr_kind { ZW_ADDR_SAPLING, ZW_ADDR_SPROUT, ZW_ADDR_PUBLIC };
struct zw_bal_row { char addr[100]; int64_t zat, confirmed_zat; bool unconfirmed; uint8_t kind; };
struct zw_balances {
    size_t n, more; /* more: addresses beyond ZW_BAL_MAX (footer row) */
    bool any_unconfirmed;
    struct zw_bal_row rows[ZW_BAL_MAX];
};
enum zw_addr_kind zw_addr_kind_of(const char *addr);

struct zw_result {
    enum zw_query kind;
    uint32_t generation;
    enum zw_err err;
    struct zw_rpc_error rpc;
    enum zw_profile profile;
    enum zw_cred cred_src;
    struct zw_chain chain;
    struct zw_net net;
    struct zw_info info;
    struct zw_wallet wallet;
    struct zw_balances *bal; /* heap; ownership moves to the model on apply */
    struct zw_locate_report report;
    uint16_t port;
    bool testnet;
    char datadir[ZW_PATH], conf_path[ZW_PATH];
};

enum zw_err zw_query_run(struct zw_rpc *r, enum zw_query q, struct zw_result *out);
void zw_result_release(struct zw_result *r);

struct zw_worker;
struct zw_worker *zw_worker_start(struct gui_window *win, const struct zw_options *o);
bool zw_worker_enqueue(struct zw_worker *w, enum zw_query q, uint32_t generation);
size_t zw_worker_drain(struct zw_worker *w, struct zw_result *out, size_t cap);
bool zw_worker_busy(struct zw_worker *w);
/* ms since the worker last made progress (a finished call or a job start); 0 when idle. */
uint64_t zw_worker_stall_ms(struct zw_worker *w);
/* How long the watchdog still waits: 0 = restart now, else the ms left of limit_ms. */
uint32_t zw_watchdog_remaining_ms(uint64_t stall_ms, uint32_t limit_ms);
int zw_worker_phase(struct zw_worker *w);
uint16_t zw_worker_port(struct zw_worker *w);
void zw_worker_reset_auth(struct zw_worker *w);
void zw_worker_restart(struct zw_worker *w); /* watchdog: abort the request in flight, locate afresh */
bool zw_worker_reset_pending(struct zw_worker *w);
void zw_worker_stop(struct zw_worker *w);
/* "worker: no reply after 6 s (phase=recv, 127.0.0.1:8023)" */
void zw_watchdog_line(int phase, uint16_t port, char *buf, size_t cap);

enum zw_conn { ZW_CONN_STARTING, ZW_CONN_NOT_FOUND, ZW_CONN_REFUSED, ZW_CONN_WARMING,
               ZW_CONN_AUTH, ZW_CONN_BAD_REPLY, ZW_CONN_ONLINE };
enum zw_sync { ZW_SYNC_CONNECTING, ZW_SYNC_SYNCED, ZW_SYNC_SYNCING, ZW_SYNC_FINDING,
               ZW_SYNC_STALE, ZW_SYNC_PEERLESS, ZW_SYNC_SKEW, ZW_SYNC_LOCAL };
enum zw_menu { ZW_MENU_NONE, ZW_MENU_FILE, ZW_MENU_EDIT, ZW_MENU_HELP, ZW_MENU_ROW };

struct zw_receive {
    struct zw_balances *list; /* Home's shield-target snapshot; owned by its caller */
    bool creating;
    char fresh_z[100];
};

struct zw_send; /* the Send page state (zw_send.h) */

struct zw_model {
    enum zw_conn conn;
    enum zw_profile requested; /* --node, for wording before anything answers */
    char conn_msg[160];
    int fail_count;
    uint32_t generation;
    bool have_chain, have_net, have_wallet, have_info;
    struct zw_chain chain;
    struct zw_net net;
    struct zw_info info;
    struct zw_wallet wallet;
    struct zw_balances *bal; /* owned; NULL until both unspent lists answered */
    struct zw_receive rcv;   /* Home shielding only; the Receive page remains a stub */
    enum zw_profile profile;
    enum zw_cred cred_src;
    uint16_t port;
    bool testnet;
    char datadir[ZW_PATH], conf_path[ZW_PATH];
    struct zw_locate_report report;
    int64_t last_update_s;    /* wall clock of the last good reply */
    int64_t now_s;            /* wall clock the view is built for */
    int warm_percent;
    int peerless_polls;
    bool ever_synced;
    /* view state the screens depend on */
    bool narrow, about_open;
    enum zw_menu menu;
    int64_t menu_row;
    char msg[120];            /* transient status-bar message */
    struct zw_send *send;     /* owned by the app; NULL when it could not be allocated */
};

void zw_model_init(struct zw_model *m, enum zw_profile requested);
void zw_model_free(struct zw_model *m);
void zw_model_watchdog(struct zw_model *m, uint16_t port);
/* Returns true when the model changed. Takes r->bal either way. */
bool zw_model_apply(struct zw_model *m, struct zw_result *r);
void zw_model_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s);
uint32_t zw_backoff_s(int fail_count);
uint32_t zw_structure_key(const struct zw_model *m, size_t screen);
void zw_diagnostics(const struct zw_model *m, char *buf, size_t cap);
enum zw_sync zw_sync_classify(const struct zw_model *m, int64_t now_s);
bool zw_model_synced(const struct zw_model *m, int64_t now_s);
const char *zw_node_kind(const struct zw_model *m); /* "zclassicd" or "Z23" */
void zw_node_line(const struct zw_model *m, char *buf, size_t cap);
void zw_version_decode(int64_t v, char *buf, size_t cap); /* 2010212 -> v2.1.2-beta13 */
void zw_connect_text(const struct zw_model *m, char *buf, size_t cap);

/* ---- shell and screens (rows come from zw_screens.def) ---- */
enum {
#define ZW_SCREEN(id, name, label, build) ZW_SCREEN_##id,
#include "zw_screens.def"
#undef ZW_SCREEN
    ZW_SCREEN_COUNT
};
struct zw_screen_row { const char *name, *label; void (*build)(struct gui_tree *, const struct zw_model *); };
extern const struct zw_screen_row zw_screens[ZW_SCREEN_COUNT];
size_t zw_screen_by_name(const char *name);

void zw_shell_build(struct gui_tree *t, const struct zw_model *m, size_t screen);
void zw_group_begin(struct gui_tree *t, const char *id, const char *title, int inset_x, int inset_top, bool grow);
void zw_group_end(struct gui_tree *t, int inset_right, int inset_bottom);
void zw_screen_connect_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_home_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_send_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_receive_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_activity_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_advanced_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_soon(struct gui_tree *t, const char *prefix, const char *title, const char *body);
/* Bound text for each part of the window (zw_model_publish calls all). */
void zw_shell_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s);
void zw_home_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s);
void zw_advanced_publish(const struct zw_model *m, struct gui_ui *ui);
/* Table sources (virtual rows) the Home screen binds. */
void zw_home_sources(struct gui_ui *ui, const struct zw_model *m);
bool zw_home_row_address(const struct zw_model *m, int64_t row, char *buf, size_t cap);

/* Per-page query hooks; later lanes fill them. */
void zw_q_send_poll(struct zw_worker *w, const struct zw_model *m);
void zw_q_receive_poll(struct zw_worker *w, const struct zw_model *m);
void zw_q_activity_poll(struct zw_worker *w, const struct zw_model *m);

/* ---- bench ---- */
struct zw_bench { int64_t first_frame_ms, first_data_ms; };
bool zw_bench_write(const char *path, const struct zw_bench *b);
int64_t zw_process_age_ms(void);
/* Real monotonic milliseconds for network deadlines: never the UI clock,
 * which is virtual under the headless backend. */
uint64_t zw_monotonic_ms(void);

/* ---- app ---- */
int zw_app_run(const struct zw_options *o);

#endif
