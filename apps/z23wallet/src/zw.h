/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the single internal header of the z23-wallet GUI program. */
#ifndef ZW_H
#define ZW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "gui/ui.h"
#include "gui/window.h"
#include "json/json.h"

#define ZW_PATH 512
#define ZW_MAX_MONEY INT64_C(2100000000000000) /* 21e6 ZCL in zatoshi */

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
size_t zw_amount_format(int64_t zat, char *buf, size_t cap, bool unit);

/* ---- locate ---- */
FILE *zw_fopen_read(const char *path_utf8);
FILE *zw_fopen_append_private(const char *path_utf8);
struct zw_endpoint {
    char host[16];
    uint16_t port;
    char datadir[ZW_PATH];
    char auth[256]; /* full "Authorization" header value; cleansed on replace */
    enum zw_profile profile;
    bool testnet, valid;
};
struct zw_locate_report {
    char tried[8][ZW_PATH];
    size_t ntried;
};
bool zw_locate(const struct zw_options *o, struct zw_endpoint *ep, struct zw_locate_report *rep);
bool zw_cookie_load(struct zw_endpoint *ep);
void zw_endpoint_wipe(struct zw_endpoint *ep);
bool zw_base64(const unsigned char *in, size_t n, char *out, size_t cap);

/* ---- http / rpc ---- */
struct zw_cancel; /* aborts the request in flight from another thread */
struct zw_cancel *zw_cancel_new(void);
void zw_cancel_free(struct zw_cancel *c);
void zw_cancel_fire(struct zw_cancel *c);
struct zw_buf { char *data; size_t len, cap; };
void zw_buf_free(struct zw_buf *b);
enum zw_err zw_http_post(const struct zw_endpoint *ep, const char *body, size_t len,
                         struct zw_buf *reply, uint32_t timeout_ms, int *http_status,
                         struct zw_cancel *cancel);

struct zw_rpc_error { int code; enum zw_err kind; char message[160]; };
struct zw_rpc {
    struct zw_endpoint ep;
    const struct zw_options *opt;
    struct zw_cancel *cancel; /* may be NULL */
    struct zw_locate_report report;
    bool missing_walletsummary, missing_gettotal;
    uint32_t next_id;
};
enum zw_err zw_rpc_call(struct zw_rpc *r, const char *method, const char *params_json,
                        struct json_value *result, struct zw_rpc_error *e);

/* ---- queries, worker, model ---- */
enum zw_query { ZW_Q_CHAIN, ZW_Q_NET, ZW_Q_WALLET, ZW_Q_COUNT };

struct zw_chain { int64_t blocks, headers; int32_t progress_permille; char chain[16]; bool provisional; };
struct zw_net { int64_t connections, inbound, outbound, version; char subversion[64]; };
struct zw_wallet {
    int64_t spendable, pending, publicf, immature, total, scanned, behind;
    bool send_allowed, current, locked, encrypted, known, legacy;
    char reason[112];
};

struct zw_result {
    enum zw_query kind;
    uint32_t generation;
    enum zw_err err;
    struct zw_rpc_error rpc;
    enum zw_profile profile;
    struct zw_chain chain;
    struct zw_net net;
    struct zw_wallet wallet;
    struct zw_locate_report report;
    uint16_t port;
    char datadir[ZW_PATH];
};

enum zw_err zw_query_run(struct zw_rpc *r, enum zw_query q, struct zw_result *out);

struct zw_worker;
struct zw_worker *zw_worker_start(struct gui_window *win, const struct zw_options *o);
bool zw_worker_enqueue(struct zw_worker *w, enum zw_query q, uint32_t generation);
size_t zw_worker_drain(struct zw_worker *w, struct zw_result *out, size_t cap);
bool zw_worker_busy(struct zw_worker *w);
void zw_worker_reset_auth(struct zw_worker *w);
void zw_worker_stop(struct zw_worker *w);

enum zw_conn { ZW_CONN_SEARCHING, ZW_CONN_REFUSED, ZW_CONN_WARMING, ZW_CONN_AUTH,
               ZW_CONN_BAD_REPLY, ZW_CONN_ONLINE };

struct zw_model {
    enum zw_conn conn;
    char conn_msg[160];
    int fail_count;
    uint32_t generation;
    bool have_chain, have_net, have_wallet;
    struct zw_chain chain;
    struct zw_net net;
    struct zw_wallet wallet;
    enum zw_profile profile;
    uint16_t port;
    char datadir[ZW_PATH];
    char tried[8][ZW_PATH];
    size_t ntried;
    int64_t last_update_s;
    int warm_percent;
};

void zw_model_init(struct zw_model *m);
/* Returns true when the model changed. */
bool zw_model_apply(struct zw_model *m, const struct zw_result *r);
void zw_model_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s);
uint32_t zw_backoff_s(int fail_count);
uint32_t zw_structure_key(const struct zw_model *m, size_t screen);
void zw_diagnostics(const struct zw_model *m, char *buf, size_t cap);

/* ---- shell and screens ---- */
enum { ZW_SCREEN_HOME, ZW_SCREEN_NODE, ZW_SCREEN_COUNT };
struct zw_action_entry { const char *name; };
void zw_shell_build(struct gui_tree *t, const struct zw_model *m, size_t screen);
void zw_screen_connect_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_home_build(struct gui_tree *t, const struct zw_model *m);
void zw_screen_node_build(struct gui_tree *t, const struct zw_model *m);
extern const struct zw_action_entry zw_screen_connect_actions[];
extern const struct zw_action_entry zw_screen_home_actions[];
extern const struct zw_action_entry zw_screen_node_actions[];

/* ---- bench ---- */
struct zw_bench { int64_t first_frame_ms, first_data_ms; };
bool zw_bench_write(const char *path, const struct zw_bench *b);
int64_t zw_process_age_ms(void);

/* ---- app ---- */
int zw_app_run(const struct zw_options *o);

#endif
