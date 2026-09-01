/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal shared state + helpers for wallet view pages.
 * Included by wallet_view_*.c files — not part of public API. */

#ifndef ZCL_CONTROLLERS_WALLET_VIEW_INTERNAL_H
#define ZCL_CONTROLLERS_WALLET_VIEW_INTERNAL_H

#include "controllers/wallet_view_controller.h"
#include "services/wallet_view_projection.h"
#include "views/wallet_view.h"
#include "views/wallet_templates_gen.h"
#include "views/format_helpers.h"
#include "controllers/explorer_internal.h"  /* APPEND macro */
#include "util/template.h"
#include "event/event.h"
#include "domain/encoding/base58.h"
#include "domain/encoding/bech32.h"
#include "chain/chainparams.h"
#include "rpc/zclassicd_port.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <sqlite3.h>
#include <unistd.h>

/* ── Constants ────────────────────────────────────────────── */

#define PRIMARY_ADDR "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
/* GUI send/shield fee: the live wallet min-relay floor (100 zat). */
#define WALLET_VIEW_FEE_ZAT 100
#define FEE_ZCL ((double)WALLET_VIEW_FEE_ZAT / (double)ZATOSHI_PER_ZCL)

/* ── Shared global state ──────────────────────────────────── */

extern const char *g_wv_datadir;
extern int g_balance_dirty;
extern time_t g_shield_pending_since;
extern char g_shield_opid[128];
extern int64_t g_shield_pending_amount;
extern bool g_sync_enabled;

/* ── DB helpers ───────────────────────────────────────────── */

sqlite3 *wv_open_db(void);
sqlite3 *wv_open_db_rw(void);
int wv_query_int(sqlite3 *db, const char *sql);
int64_t wv_query_int64(sqlite3 *db, const char *sql);
int64_t wv_query_ground_truth_balance(sqlite3 *db, int *utxo_count);
int64_t wv_query_shielded_balance(sqlite3 *db, int *note_count);
int64_t wv_query_speed_balance(sqlite3 *db);
int wv_effective_tip(sqlite3 *db);

/* ── RPC helpers ──────────────────────────────────────────── */

const char *wv_zclassicd_auth(void);
int wv_rpc_call(const char *method, const char *params,
                char *out, size_t outmax);
void wv_get_funded_taddr(char *out, size_t max);
struct wv_funded_addr { char addr[128]; double amount; };
int wv_get_all_funded_taddrs(struct wv_funded_addr *addrs, int max_addrs);
void wv_get_funded_zaddr(char *out, size_t max, double *out_balance);
void wv_sync_wallet_from_zclassicd(void);
#ifdef ZCL_TESTING
void wv_sapling_placeholder_fields_for_test(const uint8_t txid_bin[32],
                                            int outindex,
                                            uint8_t rcm[32],
                                            uint8_t ivk[32],
                                            uint8_t div_full[32],
                                            uint8_t pkd[32],
                                            uint8_t cm[32],
                                            uint8_t nf[32]);
#endif
int wv_shield_check_status(void);
struct db_contact;
int wv_recent_contacts(struct db_contact *out, size_t max);

/* ── HTML helpers ─────────────────────────────────────────── */

size_t wv_emit_header(uint8_t *buf, size_t max, const char *title,
                      const char *active_tab);
void wv_emit_footer(uint8_t *buf, size_t max, size_t *off);
size_t wv_emit_qr_svg(uint8_t *buf, size_t max, size_t off,
                       const char *data, int module_size);
size_t wv_emit_nav(uint8_t *buf, size_t max, const char *active);

/* ── Form/URL helpers ─────────────────────────────────────── */

bool wv_parse_form_field(const uint8_t *body, size_t body_len,
                         const char *key, char *out, size_t outmax);
bool wv_validate_zcl_address(const char *addr);
void wv_save_contact(const char *address, const char *name);

/* ── Format helpers ───────────────────────────────────────── */

void wv_format_relative_time(int64_t timestamp, char *out, size_t max);
void wv_format_time(int64_t timestamp, char *out, size_t max);
void wv_txid_short(const char *txid, char *out, size_t max);
void wv_txid_lower(const char *txid, char *out, size_t max);

/* ── Page handlers (each in its own .c file) ──────────────── */

size_t serve_dashboard(uint8_t *r, size_t max);
size_t serve_pulse(uint8_t *r, size_t max);
size_t serve_send(uint8_t *r, size_t max);
size_t serve_send_review(uint8_t *r, size_t max,
                          const uint8_t *body, size_t body_len);
size_t serve_send_confirm(uint8_t *r, size_t max,
                           const uint8_t *body, size_t body_len);
size_t serve_receive(uint8_t *r, size_t max);
size_t serve_history(uint8_t *r, size_t max, int page,
                      const char *filter, const char *search);
size_t serve_coins(uint8_t *r, size_t max);
size_t serve_shield(uint8_t *r, size_t max, const char *query);
size_t serve_shield_confirm(uint8_t *r, size_t max,
                             const uint8_t *body, size_t body_len);
size_t serve_tx_detail(uint8_t *r, size_t max, const char *txid);
size_t serve_node(uint8_t *r, size_t max);

#endif /* ZCL_CONTROLLERS_WALLET_VIEW_INTERNAL_H */
