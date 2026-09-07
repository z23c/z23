/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "keys/key.h"
#include "storage/dbwrapper.h"
#include "core/core_io.h"
#include "rpc/async_rpc_queue.h"
#include "validation/main_state.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"
#include "controllers/rpc_client.h"
#include "platform/clock.h"
#include "rpc/client.h"
#include "rpc/httpserver.h"
#include "rpc/legacy_rpc_client.h"
#include "services/legacy_balance_observer.h"
#include "util/ere_match.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "platform/socket_compat.h"
#include <unistd.h>
#include "test/test_rpc_priv.h"

/* Every on-disk and on-network resource this group touches must be unique to
 * this process. Two copies of the suite run concurrently (and each worktree
 * runs its own), so a fixed /tmp path or a fixed port is a cross-run
 * collision: a LevelDB LOCK held by the other run, or an EADDRINUSE from its
 * listener, fails a test that has nothing wrong with it. */
int test_rpc(void) {
    int failures = 0;
    failures += check_rpc_legacy_balance_observer_parse();
    failures += check_rpc_legacy_balance_observer_timeout();
    failures += check_rpc_json_null_bool_int_str();
    failures += check_rpc_json_object_write();
    failures += check_rpc_json_array_write();
    failures += check_rpc_json_read_object();
    failures += check_rpc_json_read_array();
    failures += check_rpc_json_roundtrip();
    failures += check_rpc_json_rpc_request_and_error();
    failures += check_rpc_diagnostics_registry_catalog();
    failures += check_rpc_dumpstate_unknown_subsystem();
    failures += check_rpc_dumpstate_help();
    failures += check_rpc_dumpstate_block_intake();
    failures += check_rpc_dumpstate_block_index();
    failures += check_rpc_legacy_rpc_parse_results();
    failures += check_rpc_legacy_rpc_timeout_table_warmup();
    failures += check_rpc_getnodelog_since_secs();
    failures += check_rpc_getnodelog_level_filter();
    failures += check_rpc_ere_matcher();
    failures += check_rpc_getnodelog_regex();
    failures += check_rpc_value_from_amount();
    failures += check_rpc_dbwrapper_open_write_read();
    failures += check_rpc_dbwrapper_batch_and_iterator();
    failures += check_rpc_convert_values();
    failures += check_rpc_convert_values_msg_send_inbox();
    failures += check_rpc_convert_msg_send_non_numeric();
    failures += check_rpc_cli_print_json_result();
    failures += check_rpc_ecc_init_sanity_check();
    failures += check_rpc_parse_script();
    failures += check_rpc_script_to_asm_str();
    failures += check_rpc_decode_hex_tx_and_parse_hash();
    failures += check_rpc_tx_to_json();
    failures += check_rpc_async_op_init_state();
    failures += check_rpc_async_op_execute_result();
    failures += check_rpc_async_op_error();
    failures += check_rpc_async_op_status_json();
    failures += check_rpc_async_queue();
    failures += check_rpc_http_tls_inactive();
    failures += check_rpc_tls_start_self_signed();
    failures += check_rpc_tls_without_env_and_port_oracle();
    return failures;
}
