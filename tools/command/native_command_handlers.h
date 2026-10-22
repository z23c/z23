/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Declares every native command handler that a catalog row binds.
 *          The rows in engine/composition/commands/ (.def files) are the single
 *          source: a new leaf names its handler in its row and needs no
 *          hand-written prototype. Included by native_command.h only.
 *
 * Each row macro below mirrors the arity of its command_catalog.c expansion.
 * Rows that bind a handler declare it; branch, compat and planned rows bind
 * none and expand to nothing. The row macros are undefined at the end. */

#ifndef ZCL_TOOLS_NATIVE_COMMAND_HANDLERS_H
#define ZCL_TOOLS_NATIVE_COMMAND_HANDLERS_H

#define ZCL_NATIVE_DECLARE_HANDLER(handler_)                                   \
    void handler_(const struct zcl_command_request *,                          \
                  struct zcl_command_reply *);

#define ZCL_COMMAND_BRANCH(path_, parent_, summary_, layer_)

#define ZCL_COMMAND_READY_READ(path_, parent_, aliases_, summary_,             \
                               semantics_, budget_, tags_,                    \
                               in_, out_, in_keys_, pos_keys_, example_,      \
                               layer_, scope_, authority_, latency_, cost_,   \
                               lanes_, caps_, traits_, transports_, handler_) \
    ZCL_NATIVE_DECLARE_HANDLER(handler_)

#define ZCL_COMMAND_COMPAT_READ(path_, parent_, aliases_, summary_,           \
                                semantics_, budget_, tags_,                   \
                                in_, out_, in_keys_, pos_keys_, example_,     \
                                layer_, scope_, authority_, latency_, cost_,  \
                                lanes_, caps_, transports_, compat_)

#define ZCL_COMMAND_PLANNED_READ(path_, parent_, aliases_, summary_,          \
                                 semantics_, budget_, tags_,                  \
                                 in_, out_, in_keys_, pos_keys_, example_,    \
                                 layer_, scope_, authority_, latency_, cost_, \
                                 lanes_, caps_, reason_)

#define ZCL_COMMAND_PLANNED_COMMAND(path_, parent_, aliases_, summary_,       \
                                    semantics_, budget_, tags_,               \
                                    in_, out_, in_keys_, pos_keys_, example_, \
                                    layer_, effect_, risk_, scope_,           \
                                    authority_, mode_, latency_, cost_,       \
                                    confirmation_, lanes_, caps_, traits_,    \
                                    reason_)

#define ZCL_COMMAND_COMPAT_COMMAND(path_, parent_, aliases_, summary_,        \
                                   semantics_, budget_, tags_,                \
                                   in_, out_, in_keys_, pos_keys_, example_,  \
                                   layer_, effect_, risk_, scope_,            \
                                   authority_, mode_, latency_, cost_,        \
                                   confirmation_, lanes_, caps_, traits_,     \
                                   reason_, compat_)

#define ZCL_COMMAND_READY_COMMAND(path_, parent_, aliases_, summary_,         \
                                  semantics_, budget_, tags_,                 \
                                  in_, out_, in_keys_, pos_keys_, example_,   \
                                  layer_, effect_, risk_, scope_,             \
                                  authority_, mode_, latency_, cost_,         \
                                  confirmation_, lanes_, caps_, traits_,      \
                                  handler_)                                   \
    ZCL_NATIVE_DECLARE_HANDLER(handler_)

#define ZCL_COMMAND_DEV_READ(path_, parent_, aliases_, summary_, semantics_,  \
                             budget_, tags_,                                  \
                             in_, out_, in_keys_, pos_keys_, example_,        \
                             scope_, authority_, latency_, cost_, lanes_,     \
                             caps_, traits_, handler_, release_reason_,       \
                             compat_)                                         \
    ZCL_NATIVE_DECLARE_HANDLER(handler_)

#define ZCL_COMMAND_DEV_COMMAND(path_, parent_, aliases_, summary_,           \
                                semantics_, budget_, tags_,                   \
                                in_, out_, in_keys_, pos_keys_, example_,     \
                                effect_, risk_, scope_, authority_, mode_,    \
                                latency_, cost_, confirmation_, lanes_,       \
                                caps_, traits_, handler_, release_reason_,    \
                                compat_)                                      \
    ZCL_NATIVE_DECLARE_HANDLER(handler_)

#include "../../engine/composition/commands/catalog.def"

#undef ZCL_COMMAND_BRANCH
#undef ZCL_COMMAND_READY_READ
#undef ZCL_COMMAND_COMPAT_READ
#undef ZCL_COMMAND_PLANNED_READ
#undef ZCL_COMMAND_PLANNED_COMMAND
#undef ZCL_COMMAND_COMPAT_COMMAND
#undef ZCL_COMMAND_READY_COMMAND
#undef ZCL_COMMAND_DEV_READ
#undef ZCL_COMMAND_DEV_COMMAND
#undef ZCL_NATIVE_DECLARE_HANDLER

#endif /* ZCL_TOOLS_NATIVE_COMMAND_HANDLERS_H */
