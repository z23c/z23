/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Blocker raised at boot when the Sapling check endpoint has no header root.
 * The loaded tree and every witness derived from it are then unverified, so
 * the wallet refuses shielded spends while the blocker is active.
 */

#ifndef ZCL_SAPLING_TIP_ROOT_BLOCKER_H
#define ZCL_SAPLING_TIP_ROOT_BLOCKER_H

#define BLOCKER_ID_SAPLING_TIP_ROOT_MISSING "sapling_tree.tip_root_missing"

#endif
