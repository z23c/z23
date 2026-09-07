/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the wallet_view scenario check files
 * (test_wallet_view.c and its test_wallet_view_*.c siblings).
 *
 * The response buffer every scenario renders into lives inside
 * struct wv_test_ctx. Sibling files never declare their own file-scope
 * mutable state — they reach the buffer only through wv_ctx(), which
 * hands back a pointer to a function-local singleton defined once in
 * test_wallet_view.c. */

#ifndef TEST_WALLET_VIEW_PRIV_H
#define TEST_WALLET_VIEW_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Seeded transparent balance: 0.05 ZCL (5,000,000 zatoshi), unspent. */
#define WV_FIX_TBAL_SAT   5000000LL
/* Seeded shielded balance: 0.02 ZCL (2,000,000 zatoshi), unspent. */
#define WV_FIX_ZBAL_SAT   2000000LL

/* Response buffer — 64KB is enough for any wallet page (sized generously
 * at 128KB). */
struct wv_test_ctx {
    uint8_t resp[131072];
};

/* Returns the single shared scenario context. Defined in
 * test_wallet_view.c as a function-local singleton. */
struct wv_test_ctx *wv_ctx(void);

/* Shared request/assertion helpers, defined in test_wallet_view.c. */
size_t wv_get(const char *path);
size_t wv_post(const char *path, const char *body);
bool wv_has(const char *needle);
bool wv_is_200(void);
double wv_perf_median_ms(const char *path, int warmup, int iters,
                          double *samples);
double wv_scan_coins_page_total(void);

/* Scenario checks — test_wallet_view.c's entry point calls every one of
 * these in order; each lives in the sibling file its scenario names. */

/* test_wallet_view_flows.c — route resolution, dashboard, send flow,
 * receive, coins, shield, transaction detail, pulse API. */
int check_wallet_view_get_wallet_returns_dashboard(void);
int check_wallet_view_get_wallet_history_returns_history_or_loading(void);
int check_wallet_view_dashboard_has_navigation_with_4_tabs(void);
int check_wallet_view_dashboard_has_recent_txs_or_loading(void);
int check_wallet_view_dashboard_has_polling_js_or_loading(void);
int check_wallet_view_send_form_has_error_display_divs(void);
int check_wallet_view_send_form_has_blur_validation_on_address_fiel(void);
int check_wallet_view_send_review_rejects_negative_amount(void);
int check_wallet_view_send_review_has_loading_overlay_for_confirm(void);
int check_wallet_view_send_confirm_with_no_provenance_evidence_refu(void);
int check_wallet_view_receive_has_qr_code_svg(void);
int check_wallet_view_receive_public_pane_hidden_by_default(void);
int check_wallet_view_coins_page_renders_no_active_nav_tab(void);
int check_wallet_view_shield_shows_fee_and_total_cost(void);
int check_wallet_view_shield_with_negative_amount_shows_form_or_not(void);
int check_wallet_view_tx_detail_with_short_txid_shows_error_or_load(void);
int check_wallet_view_pulse_returns_valid_json_structure(void);

/* test_wallet_view_consistency.c — design system, security sanitization,
 * real-data assertions, nav/css consistency, review checksum + privacy
 * warnings. */
int check_wallet_view_design_system_colors_are_consistent(void);
int check_wallet_view_path_traversal_in_tx_detail_is_sanitized(void);
int check_wallet_view_zero_size_response_buffer_doesn_t_crash(void);
int check_wallet_view_dashboard_shows_real_balance_not_loading(void);
int check_wallet_view_dashboard_recent_txs_link_to_wallet_tx_or_syn(void);
int check_wallet_view_pulse_has_peers_0(void);
int check_wallet_view_receive_qr_code_is_valid_svg(void);
int check_wallet_view_history_filter_tabs_present_and_styled(void);
int check_wallet_view_history_tx_cards_have_direction_badges(void);
int check_wallet_view_coins_page_shows_grand_total_stats(void);
int check_wallet_view_all_pages_have_consistent_nav_structure(void);
int check_wallet_view_wallet_css_loads_without_overflow(void);
int check_wallet_view_send_review_with_valid_address_shows_checksum(void);
int check_wallet_view_balance_consistent_pulse_send_coins(void);
int check_wallet_view_balance_must_be_1_zcl_sanity_check(void);
int check_wallet_view_history_shows_0_transactions(void);
int check_wallet_view_history_txs_show_non_zero_amounts(void);
int check_wallet_view_shield_review_page_renders_correctly(void);
int check_wallet_view_send_review_to_zs1_shows_t_z_privacy_warning(void);

/* test_wallet_view_resilience.c — contacts datalist, receive QR/copy
 * text, unresolved-var checks, badges/backup warning, no-DB graceful
 * degradation, oversized POST safety, titles/command-center/template
 * edge cases, render-time perf. */
int check_wallet_view_dashboard_has_contacts_datalist_on_send_page(void);
int check_wallet_view_receive_page_shows_z_address_qr_code(void);
int check_wallet_view_receive_page_says_click_to_copy_not_tap(void);
int check_wallet_view_no_unresolved_vars_in_dashboard(void);
int check_wallet_view_no_unresolved_vars_in_coins(void);
int check_wallet_view_history_cards_use_template_secured_badge(void);
int check_wallet_view_backup_warning_template_has_address(void);
int check_wallet_view_dashboard_with_no_db_renders_gracefully(void);
int check_wallet_view_send_form_still_renders_with_no_db(void);
int check_wallet_view_oversized_post_body_does_not_crash(void);
int check_wallet_view_all_titles_contain_z23(void);
int check_wallet_view_command_center_has_peer_table(void);
int check_wallet_view_template_render_handles_name_syntax(void);
int check_wallet_view_dashboard_renders_in_50ms(void);

#endif
