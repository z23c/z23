/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the rpc test scenario check files
 * (test_rpc.c and its test_rpc_*.c siblings). Each sibling keeps its
 * own file-scope helpers and fixtures (fake clocks, fake HTTP bodies,
 * tmp dirs) private to its own scenarios — nothing here is shared
 * mutable state, only the declarations the group entry point in
 * test_rpc.c needs to call every scenario across the split files. */

#ifndef TEST_RPC_PRIV_H
#define TEST_RPC_PRIV_H

/* test_rpc_legacy_and_diagnostics.c — legacy balance-observer parsing,
 * JSON value read/write/roundtrip, the diagnostics registry catalog,
 * and dumpstate subsystem checks. */
int check_rpc_legacy_balance_observer_parse(void);
int check_rpc_legacy_balance_observer_timeout(void);
int check_rpc_json_null_bool_int_str(void);
int check_rpc_json_object_write(void);
int check_rpc_json_array_write(void);
int check_rpc_json_read_object(void);
int check_rpc_json_read_array(void);
int check_rpc_json_roundtrip(void);
int check_rpc_json_rpc_request_and_error(void);
int check_rpc_diagnostics_registry_catalog(void);
int check_rpc_dumpstate_unknown_subsystem(void);
int check_rpc_dumpstate_help(void);
int check_rpc_dumpstate_block_intake(void);
int check_rpc_dumpstate_block_index(void);

/* test_rpc_legacy_and_getnodelog.c — legacy RPC parse/timeout tables
 * and the getnodelog since/level/regex family (via the ERE matcher). */
int check_rpc_legacy_rpc_parse_results(void);
int check_rpc_legacy_rpc_timeout_table_warmup(void);
int check_rpc_getnodelog_since_secs(void);
int check_rpc_getnodelog_level_filter(void);
int check_rpc_ere_matcher(void);
int check_rpc_getnodelog_regex(void);

/* test_rpc_conversion_and_transport.c — amount/value conversion,
 * dbwrapper, CLI JSON printing, script/tx parsing, the async op queue,
 * and the RPC HTTP/TLS server. */
int check_rpc_value_from_amount(void);
int check_rpc_dbwrapper_open_write_read(void);
int check_rpc_dbwrapper_batch_and_iterator(void);
int check_rpc_convert_values(void);
int check_rpc_convert_values_msg_send_inbox(void);
int check_rpc_convert_msg_send_non_numeric(void);
int check_rpc_cli_print_json_result(void);
int check_rpc_ecc_init_sanity_check(void);
int check_rpc_parse_script(void);
int check_rpc_script_to_asm_str(void);
int check_rpc_decode_hex_tx_and_parse_hash(void);
int check_rpc_tx_to_json(void);
int check_rpc_async_op_init_state(void);
int check_rpc_async_op_execute_result(void);
int check_rpc_async_op_error(void);
int check_rpc_async_op_status_json(void);
int check_rpc_async_queue(void);
int check_rpc_http_tls_inactive(void);
int check_rpc_tls_start_self_signed(void);
int check_rpc_tls_without_env_and_port_oracle(void);

#endif
