/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure BlogPost HTML rendering. No database, wallet, chain, or routing access. */

#ifndef ZCL_VIEWS_BLOG_POST_VIEW_H
#define ZCL_VIEWS_BLOG_POST_VIEW_H

#include "controllers/blog_post_controller.h"

#include <stddef.h>
#include <stdint.h>

/* Render one local BlogPost page. Returns bytes excluding NUL, or 0 when the
 * caller buffer cannot hold the complete escaped document. */
size_t blog_post_view_render(const struct blog_post_page *page,
                             uint8_t *out, size_t out_capacity);

size_t blog_post_index_view_render(const struct blog_post_index_page *page,
                                   uint8_t *out, size_t out_capacity);

#endif /* ZCL_VIEWS_BLOG_POST_VIEW_H */
