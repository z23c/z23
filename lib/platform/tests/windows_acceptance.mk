# Copyright 2026 Rhett Creighton - Apache License 2.0
# Canonical strict-C23 Windows acceptance catalog.

ZCL_WINDOWS_ACCEPTANCE_TESTS := \
	boot_auto_install_bundle_refusal \
	build_fabric_worker_refusal \
	bundle_exporter_refusal \
	consensus_bundle_marker \
	consensus_state_install_runtime_refusal \
	consensus_state_publication_cas_refusal \
	directory_compat \
	disk_space \
	file_metadata \
	format_attribute \
	glob_match \
	logical_cpu \
	mint_anchor_export_refusal \
	mint_anchor_preflight_refusal \
	package_lifecycle_store_refusal \
	positioned_file \
	positioned_io \
	private_directory \
	private_file \
	private_file_path_swap \
	read_mapping \
	rpc_client_transport \
	safe_root_read \
	socket_compat \
	ui_host_transport \
	utxo_recovery_ldb_copy_refusal \
	wallet_recovery_directory \
	workpool \
	zcode_benchmark_executor_refusal

ZCL_WINDOWS_ACCEPTANCE_boot_auto_install_bundle_refusal_SOURCES := \
	lib/test/src/boot_auto_install_bundle_windows_refusal_acceptance.c \
	config/src/boot_auto_install_bundle.c

ZCL_WINDOWS_ACCEPTANCE_build_fabric_worker_refusal_SOURCES := \
	lib/test/src/build_fabric_worker_windows_refusal_acceptance.c \
	app/services/src/build_fabric_worker_windows.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_bundle_exporter_refusal_SOURCES := \
	lib/test/src/bundle_exporter_windows_refusal_acceptance.c \
	config/src/bundle_exporter.c \
	lib/json/src/json.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_bundle_exporter_refusal_FLAGS := -DZCL_TESTING
ZCL_WINDOWS_ACCEPTANCE_consensus_bundle_marker_SOURCES := \
	lib/test/src/consensus_bundle_marker_windows_acceptance.c \
	config/src/boot_consensus_bundle_marker.c \
	lib/platform/src/private_file.c \
	lib/platform/src/file_metadata.c \
	lib/platform/src/clock.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_consensus_bundle_marker_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_consensus_state_install_runtime_refusal_SOURCES := \
	lib/test/src/consensus_state_install_runtime_windows_refusal_acceptance.c \
	config/src/consensus_state_install_runtime.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_consensus_state_publication_cas_refusal_SOURCES := \
	lib/test/src/consensus_state_publication_cas_windows_refusal_acceptance.c \
	app/services/src/consensus_state_publication_cas.c \
	app/services/src/consensus_state_publication_cas_windows.c \
	lib/sha3/src/sha3.c \
	lib/storage/src/consensus_state_bundle_codec.c \
	lib/json/src/json.c \
	lib/base/src/safe_alloc.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_consensus_state_publication_cas_refusal_FLAGS := \
	-DZCL_TESTING

ZCL_WINDOWS_ACCEPTANCE_directory_compat_SOURCES := \
	lib/platform/tests/directory_compat_windows_acceptance.c \
	lib/platform/src/directory_compat.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_disk_space_SOURCES := \
	lib/platform/tests/disk_space_windows_acceptance.c \
	lib/platform/src/disk_space.c
ZCL_WINDOWS_ACCEPTANCE_file_metadata_SOURCES := \
	lib/platform/tests/file_metadata_windows_acceptance.c \
	lib/platform/src/file_metadata.c
ZCL_WINDOWS_ACCEPTANCE_format_attribute_SOURCES := \
	lib/base/tests/format_attribute_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_glob_match_SOURCES := \
	lib/platform/tests/glob_match_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_logical_cpu_SOURCES := \
	lib/platform/tests/logical_cpu_windows_acceptance.c \
	lib/platform/src/logical_cpu.c
ZCL_WINDOWS_ACCEPTANCE_logical_cpu_FLAGS := \
	-U_WIN32_WINNT -D_WIN32_WINNT=0x0601
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_SOURCES := \
	lib/test/src/mint_anchor_export_windows_refusal_acceptance.c \
	config/src/boot_mint_anchor.c
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_FLAGS := \
	-ffunction-sections -fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_LIBS := \
	-Wl,--gc-sections
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_SOURCES := \
	lib/test/src/mint_anchor_preflight_windows_refusal_acceptance.c \
	config/src/boot_mint_anchor_preflight.c
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_SOURCES := \
	lib/test/src/package_lifecycle_store_windows_refusal_acceptance.c \
	app/services/src/package_lifecycle_store.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_FLAGS := \
	-Iapp/services/src -ffunction-sections -fno-unwind-tables \
	-fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_LIBS := \
	-Wl,--gc-sections
ZCL_WINDOWS_ACCEPTANCE_positioned_file_SOURCES := \
	lib/platform/tests/positioned_file_windows_acceptance.c \
	lib/platform/src/positioned_file.c
ZCL_WINDOWS_ACCEPTANCE_positioned_io_SOURCES := \
	lib/platform/tests/positioned_io_windows_acceptance.c \
	lib/platform/src/positioned_io.c
ZCL_WINDOWS_ACCEPTANCE_private_directory_SOURCES := \
	lib/platform/tests/private_directory_windows_acceptance.c \
	lib/platform/src/private_directory.c
ZCL_WINDOWS_ACCEPTANCE_private_directory_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_private_file_SOURCES := \
	lib/platform/tests/private_file_windows_acceptance.c \
	lib/platform/src/private_file.c \
	lib/platform/src/positioned_file.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_private_file_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_private_file_path_swap_SOURCES := \
	lib/platform/tests/private_file_path_swap_acceptance.c \
	lib/platform/src/private_file.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_private_file_path_swap_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_read_mapping_SOURCES := \
	lib/platform/tests/read_mapping_windows_acceptance.c \
	lib/platform/src/read_mapping.c
ZCL_WINDOWS_ACCEPTANCE_rpc_client_transport_SOURCES := \
	lib/platform/tests/rpc_client_transport_windows_acceptance.c \
	app/controllers/src/rpc_client.c \
	lib/json/src/json.c \
	lib/base/src/safe_alloc.c \
	lib/platform/src/clock.c
ZCL_WINDOWS_ACCEPTANCE_rpc_client_transport_LIBS := -lws2_32
ZCL_WINDOWS_ACCEPTANCE_safe_root_read_SOURCES := \
	lib/platform/tests/safe_root_read_windows_acceptance.c \
	lib/platform/src/safe_root_read.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_socket_compat_SOURCES := \
	lib/platform/tests/socket_compat_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_socket_compat_LIBS := -lws2_32
ZCL_WINDOWS_ACCEPTANCE_ui_host_transport_SOURCES := \
	lib/test/src/ui_host_transport_windows_acceptance.c \
	app/views/src/ui_present_host_transport.c \
	lib/base/src/safe_alloc.c \
	lib/platform/src/clock.c
ZCL_WINDOWS_ACCEPTANCE_ui_host_transport_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_utxo_recovery_ldb_copy_refusal_SOURCES := \
	lib/test/src/utxo_recovery_ldb_copy_windows_refusal_acceptance.c \
	app/services/src/utxo_recovery_ldb_copy.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_SOURCES := \
	lib/test/src/wallet_recovery_directory_windows_acceptance.c \
	app/services/src/wallet_recovery_service.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_file.c \
	lib/base/src/safe_alloc.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_FLAGS := \
	-DZCL_TESTING -Itools -ffunction-sections \
	-fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_LIBS := \
	-Wl,--gc-sections -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_workpool_SOURCES := \
	lib/test/src/workpool_windows_acceptance.c \
	lib/util/src/workpool.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_workpool_LIBS := -lpthread
ZCL_WINDOWS_ACCEPTANCE_zcode_benchmark_executor_refusal_SOURCES := \
	lib/test/src/zcode_benchmark_executor_windows_refusal_acceptance.c \
	app/services/src/zcode_benchmark_executor_windows.c \
	lib/base/src/result.c
