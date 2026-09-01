# Copyright 2026 Rhett Creighton - Apache License 2.0
# Canonical strict-C23 Windows acceptance catalog.

# MinGW supplies both pthread and the clock_gettime entry points used by the
# product-selected shared clock implementation from libwinpthread. This is
# also the provider the full Windows node links through top-level LIBS.
ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB := -l:libwinpthread.a

ZCL_WINDOWS_ACCEPTANCE_TESTS := \
	boot_auto_install_bundle_refusal \
	boot_export_refusal \
	build_fabric_worker_refusal \
	bundle_exporter_refusal \
	cli_render_env \
	codeindex_freshness \
	consensus_bundle_marker \
	consensus_export_fd_io_refusal \
	consensus_export_output_seal_refusal \
	consensus_install_refusal \
	consensus_state_install_runtime_refusal \
	consensus_state_publication_cas_refusal \
	database_lifetime \
	datadir_privacy \
	directory_compat \
	directory_transaction \
	disk_space \
	file_metadata \
	file_ops_copy \
	file_service_transport \
	format_attribute \
	glob_match \
	headless_run \
	hotswap_elf_probe_refusal \
	logical_cpu \
	log_level \
	mint_anchor_export_refusal \
	mint_anchor_preflight_refusal \
	nat_gateway \
	package_lifecycle_store_refusal \
	package_prepare \
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
	progress_store_refusal \
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
	sqlite_vfs_dir \
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
	tests/harness/src/boot_auto_install_bundle_windows_refusal_acceptance.c \
	engine/composition/src/boot_auto_install_bundle.c

ZCL_WINDOWS_ACCEPTANCE_boot_export_refusal_SOURCES := \
	tests/harness/src/boot_export_windows_refusal_acceptance.c \
	engine/composition/src/boot_export_consensus_bundle.c \
	platform/modules/base/src/log_level.c

ZCL_WINDOWS_ACCEPTANCE_build_fabric_worker_refusal_SOURCES := \
	tests/harness/src/build_fabric_worker_windows_refusal_acceptance.c \
	engine/services/src/build_fabric_worker_windows.c \
	platform/modules/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_bundle_exporter_refusal_SOURCES := \
	tests/harness/src/bundle_exporter_windows_refusal_acceptance.c \
	engine/composition/src/bundle_exporter.c \
	platform/modules/json/src/json.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_bundle_exporter_refusal_FLAGS := -DZCL_TESTING
ZCL_WINDOWS_ACCEPTANCE_cli_render_env_SOURCES := \
	platform/modules/platform/tests/cli_render_env_windows_acceptance.c \
	tools/command/cli_render.c \
	platform/modules/json/src/json.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_cli_render_env_FLAGS := -Itools
ZCL_WINDOWS_ACCEPTANCE_consensus_bundle_marker_SOURCES := \
	tests/harness/src/consensus_bundle_marker_windows_acceptance.c \
	engine/composition/src/boot_consensus_bundle_marker.c \
	platform/modules/platform/src/private_destination.c \
	platform/modules/platform/src/directory_compat.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/platform/src/file_metadata.c \
	platform/modules/platform/src/clock.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_consensus_bundle_marker_LIBS := \
	-ladvapi32 $(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_consensus_export_fd_io_refusal_SOURCES := \
	tests/harness/src/consensus_export_fd_io_refusal_acceptance.c \
	engine/composition/src/consensus_state_snapshot_export_fd_io.c \
	platform/modules/platform/src/positioned_io.c \
	vendor/sqlite3.c
ZCL_WINDOWS_ACCEPTANCE_consensus_export_fd_io_refusal_FLAGS := \
	-Iengine/composition/src -Wno-unused-but-set-variable -Wno-unused-parameter
ZCL_WINDOWS_ACCEPTANCE_consensus_export_output_seal_refusal_SOURCES := \
	tests/harness/src/consensus_export_output_seal_refusal_acceptance.c \
	engine/composition/src/consensus_state_snapshot_output_seal.c
ZCL_WINDOWS_ACCEPTANCE_consensus_export_output_seal_refusal_FLAGS := \
	-Iengine/composition/src
ZCL_WINDOWS_ACCEPTANCE_consensus_install_refusal_SOURCES := \
	tests/harness/src/consensus_install_windows_refusal_acceptance.c \
	engine/composition/src/consensus_state_snapshot_install.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/base/src/log_level.c \
	platform/modules/base/src/result.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_consensus_install_refusal_FLAGS := \
	-Iengine/composition/src
ZCL_WINDOWS_ACCEPTANCE_consensus_install_refusal_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_consensus_state_install_runtime_refusal_SOURCES := \
	tests/harness/src/consensus_state_install_runtime_windows_refusal_acceptance.c \
	engine/composition/src/consensus_state_install_runtime.c \
	platform/modules/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_consensus_state_publication_cas_refusal_SOURCES := \
	tests/harness/src/consensus_state_publication_cas_windows_refusal_acceptance.c \
	engine/services/src/consensus_state_publication_cas.c \
	engine/services/src/consensus_state_publication_cas_windows.c \
	platform/modules/sha3/src/sha3.c \
	engine/modules/storage/src/consensus_state_bundle_codec.c \
	platform/modules/json/src/json.c \
	platform/modules/base/src/safe_alloc.c \
	platform/modules/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_datadir_privacy_SOURCES := \
	platform/modules/platform/tests/datadir_privacy_windows_acceptance.c \
	platform/modules/util/src/util.c \
	core/chainparams/src/chainparamsbase.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_datadir_privacy_FLAGS := \
	-ffunction-sections -fdata-sections
ZCL_WINDOWS_ACCEPTANCE_datadir_privacy_LIBS := \
	-Wl,--gc-sections -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_consensus_state_publication_cas_refusal_FLAGS := \
	-DZCL_TESTING
ZCL_WINDOWS_ACCEPTANCE_consensus_state_publication_cas_refusal_LIBS := \
	$(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)

ZCL_WINDOWS_ACCEPTANCE_database_lifetime_SOURCES := \
	platform/modules/platform/tests/database_lifetime_windows_acceptance.c \
	engine/models/src/database_lifetime.c \
	platform/modules/platform/src/clock.c \
	vendor/sqlite3.c
ZCL_WINDOWS_ACCEPTANCE_database_lifetime_FLAGS := \
	-Wno-unused-but-set-variable -Wno-unused-parameter
ZCL_WINDOWS_ACCEPTANCE_database_lifetime_LIBS := \
	$(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)

ZCL_WINDOWS_ACCEPTANCE_codeindex_freshness_SOURCES := \
	tests/harness/src/codeindex_freshness_windows_acceptance.c \
	cognition/modules/codeindex/src/codeindex_build_windows.c \
	platform/modules/platform/src/directory_compat.c \
	platform/modules/base/src/safe_alloc.c \
	platform/modules/base/src/log_level.c \
	platform/modules/sha3/src/sha3.c
ZCL_WINDOWS_ACCEPTANCE_codeindex_freshness_FLAGS := \
	-DCI_WINDOWS_FRESHNESS_ONLY -Icognition/modules/codeindex/src

ZCL_WINDOWS_ACCEPTANCE_directory_compat_SOURCES := \
	platform/modules/platform/tests/directory_compat_windows_acceptance.c \
	platform/modules/platform/src/directory_compat.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_directory_transaction_SOURCES := \
	platform/modules/platform/tests/directory_transaction_windows_acceptance.c \
	platform/modules/platform/src/directory_transaction.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_directory_transaction_FLAGS := -DZCL_TESTING
ZCL_WINDOWS_ACCEPTANCE_directory_transaction_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_disk_space_SOURCES := \
	platform/modules/platform/tests/disk_space_windows_acceptance.c \
	platform/modules/platform/src/disk_space.c
ZCL_WINDOWS_ACCEPTANCE_file_metadata_SOURCES := \
	platform/modules/platform/tests/file_metadata_windows_acceptance.c \
	platform/modules/platform/src/file_metadata.c
ZCL_WINDOWS_ACCEPTANCE_file_ops_copy_SOURCES := \
	tests/harness/src/file_ops_copy_windows_acceptance.c \
	engine/composition/src/file_ops.c \
	platform/modules/platform/src/directory_compat.c \
	platform/modules/platform/src/positioned_file.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/platform/src/file_metadata.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_file_ops_copy_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_file_service_transport_SOURCES := \
	platform/modules/platform/tests/file_service_transport_windows_acceptance.c \
	core/modules/net/src/file_service_transport.c \
	core/modules/crypto/src/sha3_avx512.c \
	core/modules/crypto/src/keccak_x4.c \
	core/modules/crypto/src/simd_dispatch.c \
	platform/modules/sha3/src/sha3.c \
	platform/modules/platform/src/clock.c \
	platform/modules/base/src/cleanse.c \
	platform/modules/base/src/log_level.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_file_service_transport_LIBS := \
	-lws2_32 $(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_format_attribute_SOURCES := \
	platform/modules/base/tests/format_attribute_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_glob_match_SOURCES := \
	platform/modules/platform/tests/glob_match_windows_acceptance.c
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
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_headless_run_FLAGS := -municode
ZCL_WINDOWS_ACCEPTANCE_hotswap_elf_probe_refusal_SOURCES := \
	tests/harness/src/hotswap_elf_probe_refusal_acceptance.c \
	engine/modules/hotswap/src/hotswap_elf_probe.c \
	engine/modules/hotswap/src/hotswap_elf_probe_windows.c
ZCL_WINDOWS_ACCEPTANCE_logical_cpu_SOURCES := \
	platform/modules/platform/tests/logical_cpu_windows_acceptance.c \
	platform/modules/platform/src/logical_cpu.c
ZCL_WINDOWS_ACCEPTANCE_logical_cpu_FLAGS := \
	-U_WIN32_WINNT -D_WIN32_WINNT=0x0601
ZCL_WINDOWS_ACCEPTANCE_log_level_SOURCES := \
	tests/harness/src/log_level_acceptance.c \
	platform/modules/base/src/log_level.c
# The subject moved: boot_mint_anchor_export_bundle() and its _WIN32 refusal
# arm were split out of boot_mint_anchor.c along the E1 file-size seam, and
# this row was not updated, so the cross-link failed with an undefined
# reference. Nothing caught it because nothing ran the compile step.
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_SOURCES := \
	tests/harness/src/mint_anchor_export_windows_refusal_acceptance.c \
	engine/composition/src/boot_mint_anchor_bundle_export.c
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_FLAGS := \
	-ffunction-sections -fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_export_refusal_LIBS := \
	-Wl,--gc-sections
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_SOURCES := \
	tests/harness/src/mint_anchor_preflight_windows_refusal_acceptance.c \
	engine/composition/src/boot_mint_anchor_preflight.c \
	platform/modules/platform/src/directory_transaction.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/platform/src/rng.c platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_FLAGS := \
	-ffunction-sections -fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_LIBDEPS := \
	$(ZCL_WINDOWS_ACCEPTANCE_SQLITE)
ZCL_WINDOWS_ACCEPTANCE_mint_anchor_preflight_refusal_LIBS := \
	-Wl,--gc-sections $(ZCL_WINDOWS_ACCEPTANCE_SQLITE) -ladvapi32 -lbcrypt

ZCL_WINDOWS_ACCEPTANCE_nat_gateway_SOURCES := \
	platform/modules/platform/tests/nat_gateway_windows_acceptance.c \
	core/modules/net/src/nat.c \
	platform/modules/util/src/log_json.c \
	platform/modules/util/src/util.c \
	core/chainparams/src/chainparamsbase.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/platform/src/clock.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_nat_gateway_FLAGS := \
	-ffunction-sections -fdata-sections
ZCL_WINDOWS_ACCEPTANCE_nat_gateway_LIBS := \
	-Wl,--gc-sections -ladvapi32 -lws2_32 -liphlpapi \
	$(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)

ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_SOURCES := \
	tests/harness/src/package_lifecycle_store_windows_refusal_acceptance.c \
	contexts/commons/services/src/package_lifecycle_store.c \
	platform/modules/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_FLAGS := \
	-Iengine/services/src -ffunction-sections -fno-unwind-tables \
	-fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_package_lifecycle_store_refusal_LIBS := \
	-Wl,--gc-sections
ZCL_WINDOWS_ACCEPTANCE_package_prepare_SOURCES := \
	platform/modules/platform/tests/package_prepare_windows_acceptance.c \
	contexts/commons/modules/vcs/src/package_prepare.c \
	contexts/commons/modules/vcs/src/package_prepare_schema.c \
	contexts/commons/modules/vcs/src/package_manifest.c \
	contexts/commons/modules/vcs/src/package_recipe.c \
	platform/modules/json/src/json.c \
	platform/modules/codec/src/cursor.c \
	platform/modules/sha3/src/sha3.c \
	platform/modules/base/src/safe_alloc.c \
	platform/modules/base/src/log_level.c
ZCL_WINDOWS_ACCEPTANCE_package_prepare_FLAGS := \
	-ffunction-sections -fdata-sections
ZCL_WINDOWS_ACCEPTANCE_package_prepare_LIBS := -Wl,--gc-sections
ZCL_WINDOWS_ACCEPTANCE_os_binary_slots_refusal_SOURCES := \
	tests/harness/src/os_binary_slots_refusal_acceptance.c \
	platform/modules/platform/src/os_binary_slots.c
ZCL_WINDOWS_ACCEPTANCE_os_proc_pid_image_SOURCES := \
	platform/modules/platform/tests/os_proc_pid_image_windows_acceptance.c \
	platform/modules/platform/src/os_proc.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_os_proc_pid_image_LIBS := -ladvapi32 -lpsapi
# The SELF-image row, separate from the pid-image row above on purpose: this
# one is the only reader in the tree of the _WIN32 arm of
# os_proc_open_self_exe(), and a POSIX gcc/clang cannot see inside that arm at
# all. Deleting this row does not fail anything -- it silently returns the
# Windows running-image read to being compiled by nothing.
ZCL_WINDOWS_ACCEPTANCE_os_proc_self_image_SOURCES := \
	platform/modules/platform/tests/os_proc_self_image_windows_acceptance.c \
	platform/modules/platform/src/os_proc.c
ZCL_WINDOWS_ACCEPTANCE_os_proc_self_image_LIBS := -ladvapi32 -lpsapi -lshell32
ZCL_WINDOWS_ACCEPTANCE_pagelocker_SOURCES := \
	tests/harness/src/pagelocker_acceptance.c \
	platform/modules/support/src/pagelocker.c \
	platform/modules/base/src/cleanse.c
ZCL_WINDOWS_ACCEPTANCE_positioned_file_SOURCES := \
	platform/modules/platform/tests/positioned_file_windows_acceptance.c \
	platform/modules/platform/src/positioned_file.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_positioned_io_SOURCES := \
	platform/modules/platform/tests/positioned_io_windows_acceptance.c \
	platform/modules/platform/src/positioned_io.c
ZCL_WINDOWS_ACCEPTANCE_private_directory_SOURCES := \
	platform/modules/platform/tests/private_directory_windows_acceptance.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_private_directory_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_private_file_SOURCES := \
	platform/modules/platform/tests/private_file_windows_acceptance.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/platform/src/positioned_file.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_private_file_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_private_file_path_swap_SOURCES := \
	platform/modules/platform/tests/private_file_path_swap_acceptance.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_private_file_path_swap_LIBS := -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_process_lifecycle_SOURCES := \
	platform/modules/platform/tests/process_lifecycle_windows_acceptance.c \
	platform/modules/platform/src/process_lifecycle.c \
	platform/modules/platform/src/os_proc.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_process_lifecycle_LIBS := -lpsapi -lshell32
ZCL_WINDOWS_ACCEPTANCE_progress_store_refusal_SOURCES := \
	tests/harness/src/progress_store_windows_refusal_acceptance.c \
	engine/modules/storage/src/progress_store.c \
	engine/modules/storage/src/progress_store_directory.c \
	platform/modules/platform/src/directory_transaction.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/base/src/safe_alloc.c \
	platform/modules/base/src/log_level.c
ZCL_WINDOWS_ACCEPTANCE_progress_store_refusal_FLAGS := \
	-DZCL_PROGRESS_STORE_LEGACY_REFUSAL_ACCEPTANCE \
	-ffunction-sections -fdata-sections -flto -fwhole-program
ZCL_WINDOWS_ACCEPTANCE_progress_store_refusal_LIBS := \
	-flto -Wl,--gc-sections -ladvapi32 \
	$(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_read_mapping_SOURCES := \
	platform/modules/platform/tests/read_mapping_windows_acceptance.c \
	platform/modules/platform/src/read_mapping.c
ZCL_WINDOWS_ACCEPTANCE_rom_bundle_admission_refusal_SOURCES := \
	tests/harness/src/rom_bundle_admission_refusal_acceptance.c \
	engine/composition/src/rom_bundle_admission.c
ZCL_WINDOWS_ACCEPTANCE_rom_bundle_admission_refusal_LIBS := \
	$(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_rpc_client_transport_SOURCES := \
	platform/modules/platform/tests/rpc_client_transport_windows_acceptance.c \
	engine/controllers/src/rpc_client.c \
	platform/modules/json/src/json.c \
	platform/modules/base/src/safe_alloc.c \
	platform/modules/platform/src/clock.c
ZCL_WINDOWS_ACCEPTANCE_rpc_client_transport_LIBS := \
	-lws2_32 $(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_rng_SOURCES := \
	tests/harness/src/rng_acceptance.c \
	platform/modules/platform/src/rng.c
ZCL_WINDOWS_ACCEPTANCE_rng_LIBS := -lbcrypt
ZCL_WINDOWS_ACCEPTANCE_safe_root_read_SOURCES := \
	platform/modules/platform/tests/safe_root_read_windows_acceptance.c \
	platform/modules/platform/src/safe_root_read.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_sd_notify_unsupported_SOURCES := \
	tests/harness/src/sd_notify_unsupported_acceptance.c \
	platform/modules/util/src/sd_notify.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_candidate_output_refusal_SOURCES := \
	tests/harness/src/snapshot_candidate_output_refusal_acceptance.c \
	engine/composition/src/consensus_state_snapshot_candidate_output.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_candidate_output_refusal_FLAGS := -Iengine/composition/src
ZCL_WINDOWS_ACCEPTANCE_snapshot_export_refusal_SOURCES := \
	tests/harness/src/snapshot_export_refusal_acceptance.c \
	engine/composition/src/consensus_state_snapshot_export_windows.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_export_refusal_FLAGS := -Iengine/composition/src
ZCL_WINDOWS_ACCEPTANCE_snapshot_install_activate_refusal_SOURCES := \
	tests/harness/src/snapshot_install_activate_refusal_acceptance.c \
	engine/composition/src/consensus_state_snapshot_install_activate_windows.c
ZCL_WINDOWS_ACCEPTANCE_snapshot_install_activate_refusal_FLAGS := -Iengine/composition/src
ZCL_WINDOWS_ACCEPTANCE_socket_compat_SOURCES := \
	platform/modules/platform/tests/socket_compat_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_socket_compat_LIBS := -lws2_32
# The retained-directory SQLite VFS proof binds its source-local private ACL
# header by relative include, so this row does not broaden the include search
# path to all of platform/modules/platform/src. The vendored amalgamation links from the
# private acceptance archive ($(ZCL_WINDOWS_ACCEPTANCE_SQLITE) in the top
# Makefile), keeping the strict flags on our own sources only.
ZCL_WINDOWS_ACCEPTANCE_sqlite_vfs_dir_SOURCES := \
	tests/harness/src/sqlite_vfs_dir_windows_acceptance.c \
	engine/modules/storage/src/sqlite_vfs_dir_windows.c \
	engine/modules/storage/src/sqlite_vfs_dir_windows_registration.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_sqlite_vfs_dir_LIBDEPS := \
	engine/modules/storage/src/sqlite_vfs_dir_windows_internal.h \
	$(ZCL_WINDOWS_ACCEPTANCE_SQLITE)
ZCL_WINDOWS_ACCEPTANCE_sqlite_vfs_dir_LIBS := \
	$(ZCL_WINDOWS_ACCEPTANCE_SQLITE) -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_stale_lock_capability_SOURCES := \
	tests/harness/src/stale_lock_capability_acceptance.c \
	platform/modules/platform/src/os_proc.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_stale_lock_capability_LIBS := -ladvapi32 -lpsapi
ZCL_WINDOWS_ACCEPTANCE_state_root_SOURCES := \
	platform/modules/platform/tests/state_root_windows_acceptance.c \
	platform/modules/platform/src/state_root.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_state_root_LIBS := -ladvapi32 -lshell32 -lole32 -luuid
ZCL_WINDOWS_ACCEPTANCE_thread_join_SOURCES := \
	platform/modules/platform/tests/thread_join_windows_acceptance.c
ZCL_WINDOWS_ACCEPTANCE_thread_join_LIBS := \
	$(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_ui_host_transport_SOURCES := \
	tests/harness/src/ui_host_transport_windows_acceptance.c \
	contexts/explorer/views/src/ui_present_host_transport.c \
	platform/modules/base/src/safe_alloc.c \
	platform/modules/platform/src/clock.c
ZCL_WINDOWS_ACCEPTANCE_ui_host_transport_LIBS := \
	-ladvapi32 $(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_utxo_recovery_ldb_copy_refusal_SOURCES := \
	tests/harness/src/utxo_recovery_ldb_copy_windows_refusal_acceptance.c \
	engine/services/src/utxo_recovery_ldb_copy.c \
	platform/modules/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_SOURCES := \
	tests/harness/src/wallet_recovery_directory_windows_acceptance.c \
	contexts/wallet/services/src/wallet_recovery_service.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/platform/src/private_file.c \
	platform/modules/base/src/safe_alloc.c \
	platform/modules/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_FLAGS := \
	-DZCL_TESTING -Itools -ffunction-sections \
	-fno-unwind-tables -fno-asynchronous-unwind-tables
ZCL_WINDOWS_ACCEPTANCE_wallet_recovery_directory_LIBS := \
	-Wl,--gc-sections -ladvapi32
ZCL_WINDOWS_ACCEPTANCE_wallet_restore_refusal_SOURCES := \
	tests/harness/src/wallet_restore_windows_refusal_acceptance.c \
	contexts/wallet/services/src/wallet_restore_service.c \
	platform/modules/base/src/result.c
ZCL_WINDOWS_ACCEPTANCE_watcher_lease_SOURCES := \
	platform/modules/platform/tests/watcher_lease_windows_acceptance.c \
	platform/modules/platform/src/watcher_lease.c \
	platform/modules/platform/src/process_lifecycle.c \
	platform/modules/platform/src/current_identity.c \
	platform/modules/platform/src/directory_compat.c \
	platform/modules/platform/src/os_proc.c \
	platform/modules/platform/src/positioned_file.c \
	platform/modules/platform/src/rng.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_watcher_lease_LIBS := \
	-ladvapi32 -lpsapi -lshell32 -lbcrypt
ZCL_WINDOWS_ACCEPTANCE_watcher_store_SOURCES := \
	platform/modules/platform/tests/watcher_store_windows_acceptance.c \
	platform/modules/platform/src/watcher_store.c \
	platform/modules/platform/src/directory_transaction.c \
	platform/modules/platform/src/private_directory.c \
	platform/modules/platform/src/private_acl_internal.c \
	platform/modules/platform/src/rng.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_watcher_store_LIBS := -ladvapi32 -lbcrypt
ZCL_WINDOWS_ACCEPTANCE_workpool_SOURCES := \
	tests/harness/src/workpool_windows_acceptance.c \
	platform/modules/util/src/workpool.c \
	platform/modules/base/src/safe_alloc.c
ZCL_WINDOWS_ACCEPTANCE_workpool_LIBS := \
	$(ZCL_WINDOWS_ACCEPTANCE_PTHREAD_LIB)
ZCL_WINDOWS_ACCEPTANCE_zcode_benchmark_executor_refusal_SOURCES := \
	tests/harness/src/zcode_benchmark_executor_windows_refusal_acceptance.c \
	contexts/commons/services/src/zcode_benchmark_executor_windows.c \
	platform/modules/base/src/result.c
