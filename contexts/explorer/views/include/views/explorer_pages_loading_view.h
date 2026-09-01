/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer pages loading view — token-index status served while its
 * background cache warms. The controller parses the request and delegates the
 * HTML/HTTP assembly here. */

#ifndef ZCL_VIEWS_EXPLORER_PAGES_LOADING_VIEW_H
#define ZCL_VIEWS_EXPLORER_PAGES_LOADING_VIEW_H

#include <stdint.h>
#include <stddef.h>

/* Render the tokens-page index status into r. Returns bytes written. */
size_t explorer_view_tokens_loading(uint8_t *r, size_t max);

#endif
