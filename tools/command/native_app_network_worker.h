/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare the isolated app network worker entry. */
#ifndef ZCL_NATIVE_APP_NETWORK_WORKER_H
#define ZCL_NATIVE_APP_NETWORK_WORKER_H
/* Called only for the reserved early entry; malformed arguments refuse. */
int app_network_worker_main(int argc, char **argv);
#if defined(ZCL_TESTING) && !defined(_WIN32)
struct vcs_package_store;
struct vcs_package_store *zcl_test_app_network_worker_store_open(const char *datadir);
#endif
#endif
