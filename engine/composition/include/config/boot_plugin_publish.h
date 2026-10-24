/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resident RPC plugin_publish_commit: the running package host
 *          verifies a release a CLI signed offline and commits the package
 *          into its OWN resident store, so no second process writes it. */
#ifndef ZCL_CONFIG_BOOT_PLUGIN_PUBLISH_H
#define ZCL_CONFIG_BOOT_PLUGIN_PUBLISH_H

struct rpc_table;
struct json_value;
struct vcs_package_store;

void boot_plugin_publish_register_rpc(struct rpc_table *table);

/* The whole handler against explicit handles (the RPC passes the node's own;
 * a test passes fixtures). `in` is the one input object; `store` NULL means
 * hosting is off. `scratch_dir` is a private directory for the license copy.
 * Fills `result` with the reply; never writes the store before every check. */
void boot_plugin_publish_commit_run(const struct json_value *in, struct vcs_package_store *store,
                                    const char *plugins_dir, const char *scratch_dir,
                                    struct json_value *result);

#endif
