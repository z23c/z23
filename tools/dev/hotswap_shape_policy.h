/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared lexical path boundaries for hot-swap shape advice. */
#ifndef Z23_HOTSWAP_SHAPE_POLICY_H
#define Z23_HOTSWAP_SHAPE_POLICY_H
#define ZCL_HOTSWAP_SHAPE_ALLOWED \
    "^(engine|cognition|contexts/[^/]+)/(controllers|views|conditions)/"
#define ZCL_HOTSWAP_ISLAND_ALLOWED \
    "^(engine|cognition|contexts/[^/]+)/(controllers|views|conditions|" \
    "services)/.+\\.c$|^contexts/commons/modules/metaverse/src/.+\\.c$|" \
    "^platform/modules/encoding/src/.+\\.c$|" \
    "^contexts/commons/modules/vcs/src/package_policy\\.c$"
#define ZCL_HOTSWAP_SHAPE_FORBIDDEN \
    "^(core/(consensus|modules/(validation|net|coins|chain|mining))|" \
    "engine/(reducer|jobs|supervisors|modules/(storage|kernel|" \
    "supervisor)))/"
#endif
