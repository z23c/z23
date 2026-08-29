# Copyright 2026 Rhett Creighton - Apache License 2.0
# Canonical strict-C23 Windows acceptance catalog.

ZCL_WINDOWS_ACCEPTANCE_TESTS := \
	boot_auto_install_bundle_refusal \
	boot_export_refusal \
	build_fabric_worker_refusal \
	bundle_exporter_refusal \
	cli_render_env \
	codeindex_build_refusal \
	consensus_bundle_marker \
	consensus_export_fd_io_refusal \
	consensus_export_output_seal_refusal \
	consensus_install_refusal \
	consensus_state_install_runtime_refusal \
	consensus_state_publication_cas_refusal \
	datadir_privacy \
	directory_compat \
	directory_transaction \
	disk_space \
	file_metadata \
	file_ops_copy \
	format_attribute \
	glob_match \
	headless_run \
	hotswap_elf_probe_refusal \
	logical_cpu \
	log_level \
	mint_anchor_export_refusal \
	mint_anchor_preflight_refusal \
	package_lifecycle_store_refusal \
	os_binary_slots_refusal \
	os_proc_pid_image \
	os_proc_self_image \
	pagelocker \
	positioned_file \
	positioned_io \
	private_directory \
	private_file \
	private_file_path_swap \
	process_lifecycle \
	read_mapping \
	rom_bundle_admission_refusal \
	rpc_client_transport \
	rng \
	safe_root_read \
	sd_notify_unsupported \
	snapshot_candidate_output_refusal \
	snapshot_export_refusal \
	snapshot_install_activate_refusal \
	socket_compat \
	stale_lock_capability \
	state_root \
	thread_join \
	ui_host_transport \
	utxo_recovery_ldb_copy_refusal \
	wallet_recovery_directory \
	wallet_restore_refusal \
	watcher_lease \
	watcher_store \
	workpool \
	zcode_benchmark_executor_refusal

ZCL_WINDOWS_ACCEPTANCE_boot_auto_install_bundle_refusal_SOURCES := \
	lib/test/src/boot_auto_install_bundle_windows_refusal_acceptance.c \
	config/src/boot_auto_install_bundle.c

ZCL_WINDOWS_ACCEPTANCE_boot_export_refusal_SOURCES := \
	lib/test/src/boot_export_windows_refusal_acceptance.c \
	config/src/boot_export_consensus_bundle.c \
	lib/base/src/log_level.c

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
ZCL_WINDOWS_ACCEPTANCE_cli_render_env_SOURCES := \
	lib/platform/tests/cli_render_env_windows_acceptance.c \
	tools/command/cli_render.c \
	lib/json/src/json.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_cli_render_env_FLAGS := -Itools
ZCL_WINDOWS_ACCEPTANCE_codeindex_build_refusal_SOURCES := \
	lib/test/src/codeindex_build_refusal_acceptance.c \
	lib/codeindex/src/codeindex_build_windows.c
ZCL_WINDOWS_ACCEPTANCE_codeindex_build_refusal_FLAGS := -Ilib/codeindex/src
ZCL_WINDOWS_ACCEPTANCE_consensus_bundle_marker_SOURCES := \
	lib/test/src/consensus_bundle_marker_windows_acceptance.c \
	config/src/boot_consensus_bundle_marker.c \
	lib/platform/src/private_destination.c \
	lib/platform/src/directory_compat.c \
	lib/platform/src/private_file.c \
	lib/platform/src/file_metadata.c \
	lib/platform/src/clock.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_consensus_bundle_marker_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_consensus_export_fd_io_refusal_SOURCES := \
	lib/test/src/consensus_export_fd_io_refusal_acceptance.c \
	config/src/consensus_state_snapshot_export_fd_io.c \
	lib/platform/src/positioned_io.c \
	vendor/sqlite3.c
ZCL_WINDOWS_ACCEPTANCE_consensus_export_fd_io_refusal_FLAGS := \
	-Iconfig/src -Wno-unused-but-set-variable -Wno-unused-parameter
ZCL_WINDOWS_ACCEPTANCE_consensus_export_output_seal_refusal_SOURCES := \
	lib/test/src/consensus_export_output_seal_refusal_acceptance.c \
	config/src/consensus_state_snapshot_output_seal.c
ZCL_WINDOWS_ACCEPTANCE_consensus_export_output_seal_refusal_FLAGS := \
	-Iconfig/src
ZCL_WINDOWS_ACCEPTANCE_consensus_install_refusal_SOURCES := \
	lib/test/src/consensus_install_windows_refusal_acceptance.c \
	config/src/consensus_state_snapshot_install.c \
	lib/platform/src/private_file.c \
	lib/base/src/log_level.c \
	lib/base/src/result.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_consensus_install_refusal_FLAGS := \
	-Iconfig/src
ZCL_WINDOWS_ACCEPTANCE_consensus_install_refusal_LIBS := -ladvapi32
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
ZCL_WINDOWS_ACCEPTANCE_datadir_privacy_SOURCES := \
	lib/platform/tests/datadir_privacy_windows_acceptance.c \
	lib/util/src/util.c \
	core/chainparams/src/chainparamsbase.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_acl_internal.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_datadir_privacy_FLAGS := \
	-ffunction-sections -fdata-sections
ZCL_WINDOWS_ACCEPTANCE_datadir_privacy_LIBS := \
	-Wl,--gc-sections -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_consensus_state_publication_cas_refusal_FLAGS := \
	-DZCL_TESTING

ZCL_WINDOWS_ACCEPTANCE_directory_compat_SOURCES := \
	lib/platform/tests/directory_compat_windows_acceptance.c \
	lib/platform/src/directory_compat.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_directory_transaction_SOURCES := \
	lib/platform/tests/directory_transaction_windows_acceptance.c \
	lib/platform/src/directory_transaction.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_acl_internal.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_directory_transaction_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_disk_space_SOURCES := \
	lib/platform/tests/disk_space_windows_acceptance.c \
	lib/platform/src/disk_space.c
ZCL_WINDOWS_ACCEPTANCE_file_metadata_SOURCES := \
	lib/platform/tests/file_metadata_windows_acceptance.c \
	lib/platform/src/file_metadata.c
ZCL_WINDOWS_ACCEPTANCE_file_ops_copy_SOURCES := \
	lib/test/src/file_ops_copy_windows_acceptance.c \
	config/src/file_ops.c \
	lib/platform/src/directory_compat.c \
	lib/platform/src/positioned_file.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_acl_internal.c \
	lib/platform/src/private_file.c \
	lib/platform/src/file_metadata.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_file_ops_copy_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_format_attribute_SOURCES := \
	lib/base/tests/format_attribute_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_glob_match_SOURCES := \
	lib/platform/tests/glob_match_windows_acceptance.c
# ── The Windows-only headless process launcher ──────────────────────────────
# tools/dev/windows_headless_run.c is NOT a platform-seam acceptance program
# like every other row here: it is a standalone TOOL. Its
# $(BIN_DIR)/z23-headless-run.exe rule in the top-level Makefile is written
# entirely inside `ifeq ($(ZCL_HOST_WINDOWS),1)` -- the else arm defines only
# phony goals that print "windows headless runner requires native Windows" and
# fail -- so on a POSIX host make has NO RULE for that target at all, and
# check-standalone-tools-link (the gate whose whole point is "a Makefile tool
# rule that nothing else builds rots silently") cannot build it.
#
# That gate therefore host-exempts the target and points HERE for the
# replacement evidence. This row is the ONLY thing on a POSIX host that proves
# the source still compiles and links for Windows; delete it and the exemption
# over there becomes exactly the rot the gate exists to stop. The coupling is
# not a comment: check_standalone_tools_link.sh reads this file and refuses
# (exit 2) if it stops naming tools/dev/windows_headless_run.c.
#
# STANDARD NOTE -- deliberate, not a silent divergence. The native Makefile
# rule compiles this file with -std=c23. This catalog compiles every row with
# -std=c2x (ZCL_WINDOWS_ACCEPTANCE_FLAGS) because the mingw driver installed
# as x86_64-w64-mingw32-gcc (GCC 13) rejects -std=c23 outright with
# "unrecognized command-line option '-std=c23'". c2x is that same language
# under its pre-ratification spelling, so this is one compiler driver's
# spelling, not a weaker standard. -municode is required and not optional: the
# program's entry point is wmain(), and without it the link has no entry.
# The launcher stopped being a single self-contained translation unit when
# its allocations moved onto the shared wrappers, so it needs their
# definition. Compiled at -std=c2x because the mingw here rejects -std=c23;
# the native Windows rule in the top-level Makefile uses -std=c23.
ZCL_WINDOWS_ACCEPTANCE_headless_run_SOURCES := \
	tools/dev/windows_headless_run.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_headless_run_FLAGS := -municode
ZCL_WINDOWS_ACCEPTANCE_hotswap_elf_probe_refusal_SOURCES := \
	lib/test/src/hotswap_elf_probe_refusal_acceptance.c \
	lib/hotswap/src/hotswap_elf_probe.c \
	lib/hotswap/src/hotswap_elf_probe_windows.c
ZCL_WINDOWS_ACCEPTANCE_logical_cpu_SOURCES := \
	lib/platform/tests/logical_cpu_windows_acceptance.c \
	lib/platform/src/logical_cpu.c
ZCL_WINDOWS_ACCEPTANCE_logical_cpu_FLAGS := \
	-U_WIN32_WINNT -D_WIN32_WINNT=0x0601
ZCL_WINDOWS_ACCEPTANCE_log_level_SOURCES := \
	lib/test/src/log_level_acceptance.c \
	lib/base/src/log_level.c
# The subject moved: boot_mint_anchor_export_bundle() and its _WIN32 refusal
# arm were split out of boot_mint_anchor.c along the E1 file-size seam, and
# this row was not updated, so the cross-link failed with an undefined
# reference. Nothing caught it because nothing ran the compile step.
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_SOURCES := \
	lib/test/src/mint_anchor_export_windows_refusal_acceptance.c \
	config/src/boot_mint_anchor_bundle_export.c
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_FLAGS := \
	-ffunction-sections -fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_LIBS := \
	-Wl,--gc-sections
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_SOURCES := \
	lib/test/src/mint_anchor_preflight_windows_refusal_acceptance.c \
	config/src/boot_mint_anchor_preflight.c \
	lib/platform/src/directory_transaction.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_acl_internal.c \
	lib/platform/src/rng.c lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_FLAGS := \
	-ffunction-sections -fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_LIBDEPS := \
	$(ZCL_WINDOWS_ACCEPTANCE_SQLITE)
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_LIBS := \
	-Wl,--gc-sections $(ZCL_WINDOWS_ACCEPTANCE_SQLITE) -ladvapi32 -lbcrypt
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_SOURCES := \
	lib/test/src/package_lifecycle_store_windows_refusal_acceptance.c \
	app/services/src/package_lifecycle_store.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_FLAGS := \
	-Iapp/services/src -ffunction-sections -fno-unwind-tables \
	-fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_LIBS := \
	-Wl,--gc-sections
ZCL_WINDOWS_ACCEPTANCE_os_binary_slots_refusal_SOURCES := \
	lib/test/src/os_binary_slots_refusal_acceptance.c \
	lib/platform/src/os_binary_slots.c
ZCL_WINDOWS_ACCEPTANCE_os_proc_pid_image_SOURCES := \
	lib/platform/tests/os_proc_pid_image_windows_acceptance.c \
	lib/platform/src/os_proc.c \
	lib/platform/src/private_file.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_os_proc_pid_image_LIBS := -ladvapi32 -lpsapi
# The SELF-image row, separate from the pid-image row above on purpose: this
# one is the only reader in the tree of the _WIN32 arm of
# os_proc_open_self_exe(), and a POSIX gcc/clang cannot see inside that arm at
# all. Deleting this row does not fail anything -- it silently returns the
# Windows running-image read to being compiled by nothing.
ZCL_WINDOWS_ACCEPTANCE_os_proc_self_image_SOURCES := \
	lib/platform/tests/os_proc_self_image_windows_acceptance.c \
	lib/platform/src/os_proc.c
ZCL_WINDOWS_ACCEPTANCE_os_proc_self_image_LIBS := -ladvapi32 -lpsapi -lshell32
ZCL_WINDOWS_ACCEPTANCE_pagelocker_SOURCES := \
	lib/test/src/pagelocker_acceptance.c \
	lib/support/src/pagelocker.c \
	lib/base/src/cleanse.c
ZCL_WINDOWS_ACCEPTANCE_positioned_file_SOURCES := \
	lib/platform/tests/positioned_file_windows_acceptance.c \
	lib/platform/src/positioned_file.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_positioned_io_SOURCES := \
	lib/platform/tests/positioned_io_windows_acceptance.c \
	lib/platform/src/positioned_io.c
ZCL_WINDOWS_ACCEPTANCE_private_directory_SOURCES := \
	lib/platform/tests/private_directory_windows_acceptance.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_acl_internal.c \
	lib/base/src/safe_alloc.c
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
ZCL_WINDOWS_ACCEPTANCE_process_lifecycle_SOURCES := \
	lib/platform/tests/process_lifecycle_windows_acceptance.c \
	lib/platform/src/process_lifecycle.c \
	lib/platform/src/os_proc.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_process_lifecycle_LIBS := -lpsapi -lshell32
ZCL_WINDOWS_ACCEPTANCE_read_mapping_SOURCES := \
	lib/platform/tests/read_mapping_windows_acceptance.c \
	lib/platform/src/read_mapping.c
ZCL_WINDOWS_ACCEPTANCE_rom_bundle_admission_refusal_SOURCES := \
	lib/test/src/rom_bundle_admission_refusal_acceptance.c \
	config/src/rom_bundle_admission.c
ZCL_WINDOWS_ACCEPTANCE_rpc_client_transport_SOURCES := \
	lib/platform/tests/rpc_client_transport_windows_acceptance.c \
	app/controllers/src/rpc_client.c \
	lib/json/src/json.c \
	lib/base/src/safe_alloc.c \
	lib/platform/src/clock.c
ZCL_WINDOWS_ACCEPTANCE_rpc_client_transport_LIBS := -lws2_32
ZCL_WINDOWS_ACCEPTANCE_rng_SOURCES := \
	lib/test/src/rng_acceptance.c \
	lib/platform/src/rng.c
ZCL_WINDOWS_ACCEPTANCE_rng_LIBS := -lbcrypt
ZCL_WINDOWS_ACCEPTANCE_safe_root_read_SOURCES := \
	lib/platform/tests/safe_root_read_windows_acceptance.c \
	lib/platform/src/safe_root_read.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_sd_notify_unsupported_SOURCES := \
	lib/test/src/sd_notify_unsupported_acceptance.c \
	lib/util/src/sd_notify.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_candidate_output_refusal_SOURCES := \
	lib/test/src/snapshot_candidate_output_refusal_acceptance.c \
	config/src/consensus_state_snapshot_candidate_output.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_candidate_output_refusal_FLAGS := -Iconfig/src
ZCL_WINDOWS_ACCEPTANCE_snapshot_export_refusal_SOURCES := \
	lib/test/src/snapshot_export_refusal_acceptance.c \
	config/src/consensus_state_snapshot_export_windows.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_export_refusal_FLAGS := -Iconfig/src
ZCL_WINDOWS_ACCEPTANCE_snapshot_install_activate_refusal_SOURCES := \
	lib/test/src/snapshot_install_activate_refusal_acceptance.c \
	config/src/consensus_state_snapshot_install_activate_windows.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_install_activate_refusal_FLAGS := -Iconfig/src
ZCL_WINDOWS_ACCEPTANCE_socket_compat_SOURCES := \
	lib/platform/tests/socket_compat_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_socket_compat_LIBS := -lws2_32
ZCL_WINDOWS_ACCEPTANCE_stale_lock_capability_SOURCES := \
	lib/test/src/stale_lock_capability_acceptance.c \
	lib/platform/src/os_proc.c \
	lib/platform/src/private_file.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_stale_lock_capability_LIBS := -ladvapi32 -lpsapi
ZCL_WINDOWS_ACCEPTANCE_state_root_SOURCES := \
	lib/platform/tests/state_root_windows_acceptance.c \
	lib/platform/src/state_root.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_acl_internal.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_state_root_LIBS := -ladvapi32 -lshell32 -lole32 -luuid
ZCL_WINDOWS_ACCEPTANCE_thread_join_SOURCES := \
	lib/platform/tests/thread_join_windows_acceptance.c
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
	lib/platform/src/private_acl_internal.c \
	lib/platform/src/private_file.c \
	lib/base/src/safe_alloc.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_FLAGS := \
	-DZCL_TESTING -Itools -ffunction-sections \
	-fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_LIBS := \
	-Wl,--gc-sections -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_wallet_restore_refusal_SOURCES := \
	lib/test/src/wallet_restore_windows_refusal_acceptance.c \
	app/services/src/wallet_restore_service.c \
	lib/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_watcher_lease_SOURCES := \
	lib/platform/tests/watcher_lease_windows_acceptance.c \
	lib/platform/src/watcher_lease.c \
	lib/platform/src/process_lifecycle.c \
	lib/platform/src/current_identity.c \
	lib/platform/src/directory_compat.c \
	lib/platform/src/os_proc.c \
	lib/platform/src/positioned_file.c \
	lib/platform/src/rng.c \
	lib/platform/src/private_acl_internal.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_watcher_lease_LIBS := \
	-ladvapi32 -lpsapi -lshell32 -lbcrypt
ZCL_WINDOWS_ACCEPTANCE_watcher_store_SOURCES := \
	lib/platform/tests/watcher_store_windows_acceptance.c \
	lib/platform/src/watcher_store.c \
	lib/platform/src/directory_transaction.c \
	lib/platform/src/private_directory.c \
	lib/platform/src/private_acl_internal.c \
	lib/platform/src/rng.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_watcher_store_LIBS := -ladvapi32 -lbcrypt
ZCL_WINDOWS_ACCEPTANCE_workpool_SOURCES := \
	lib/test/src/workpool_windows_acceptance.c \
	lib/util/src/workpool.c \
	lib/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_workpool_LIBS := -lpthread
ZCL_WINDOWS_ACCEPTANCE_zcode_benchmark_executor_refusal_SOURCES := \
	lib/test/src/zcode_benchmark_executor_windows_refusal_acceptance.c \
	app/services/src/zcode_benchmark_executor_windows.c \
	lib/base/src/result.c
