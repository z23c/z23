/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BlogPost resource controller. Thin Rails-style orchestration only:
 * validate typed request shape, call one publication service/model method,
 * and return a typed page to the view. */

#ifndef ZCL_CONTROLLERS_BLOG_POST_CONTROLLER_H
#define ZCL_CONTROLLERS_BLOG_POST_CONTROLLER_H

#include "services/blog_publication_service.h"

struct blog_post_page {
    struct db_blog_post post;
    bool has_receipt;
    struct db_blog_publication_receipt receipt;
    bool content_available;
    bool served_frontier_proven;
};

#define BLOG_POST_INDEX_MAX 32

struct blog_post_index_page {
    char blog_name[BLOG_NAME_MAX + 1]; /* empty = all names */
    struct db_blog_post_summary posts[BLOG_POST_INDEX_MAX];
    int count;
};

struct rpc_table;

/* Operator-only chain-anchor RPC. Public HTTP remains read-only; the handler
 * consumes the shared wallet RPC context rather than owning a second copy. */
void register_blog_post_rpc_commands(struct rpc_table *table);

struct zcl_result blog_post_controller_create(
    struct node_db *ndb, struct wallet *wallet,
    const struct zcl_app_event_signing_binding_v1 *binding,
    const struct blog_publish_request *request,
    struct blog_publish_result *out);

struct zcl_result blog_post_controller_import(
    struct node_db *ndb, const struct zcl_app_signed_event_v1 *event,
    struct db_blog_post *out);

struct zcl_result blog_post_controller_show(
    struct node_db *ndb, const char *blog_name, const char *slug,
    struct blog_post_page *out);

struct zcl_result blog_post_controller_index(
    struct node_db *ndb, const char *blog_name_or_null,
    struct blog_post_index_page *out);

/* Public read-only site mount used by both HTTPS (zclnet.net/blog) and each
 * node's onion service. Returns a complete HTTP response. Signed-event
 * creation remains broker-contained; app.blog.anchor is an operator-only
 * plan/commit for an event that is already stored and verified. */
size_t blog_site_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max);

#endif /* ZCL_CONTROLLERS_BLOG_POST_CONTROLLER_H */
