/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: modal dialog builders (gui/dialog.h). They only add nodes to the
 * tree: modality, Escape, Enter-on-default, focus scope and layout are the
 * GUI_DIALOG rules of ui_input.c and ui_layout.c. */
#include <stdio.h>

#include "gui/dialog.h"

void gui_dialog_open(struct gui_tree *t, const char *id, const char *title, const char *cancel_action,
                     int32_t width)
{
    gui_dialog(t, id, title && title[0] ? title : " ", cancel_action);
    if (width > 0) gui_attr(t, GUI_A_W, width);
}

void gui_dialog_close(struct gui_tree *t) { gui_end(t); }

void gui_dialog_buttons(struct gui_tree *t, const char *row_id, const struct gui_dialog_button *b, size_t n)
{
    gui_box(t, row_id, GUI_ROW, GS_DIALOG);
    gui_attr(t, GUI_A_GAP, 8);
    gui_spacer(t, 1);
    for (size_t i = 0; i < n; i++) {
        gui_button(t, b[i].id, b[i].style, b[i].label, b[i].action);
        gui_attr(t, GUI_A_H, 36);
        if (b[i].is_default) gui_flag(t, GUI_F_DEFAULT);
        if (b[i].disabled) gui_flag(t, GUI_F_DISABLED);
    }
    gui_end(t);
}

void gui_msgbox(struct gui_tree *t, const char *id, const char *title, const char *body, const char *detail,
                const struct gui_dialog_button *b, size_t n, const char *cancel_action, int32_t width)
{
    char sub[GUI_ID_MAX];
    gui_dialog_open(t, id, title, cancel_action, width);
    snprintf(sub, sizeof(sub), "%.24s_body", id);
    gui_text(t, sub, GS_DIALOG, body);
    gui_flag(t, GUI_F_WRAP | GUI_F_SELECTABLE);
    if (detail && detail[0]) {
        snprintf(sub, sizeof(sub), "%.24s_detail", id);
        gui_text(t, sub, GS_MUTED, detail);
        gui_flag(t, GUI_F_WRAP | GUI_F_SELECTABLE);
    }
    snprintf(sub, sizeof(sub), "%.24s_btns", id);
    gui_dialog_buttons(t, sub, b, n);
    gui_dialog_close(t);
}

void gui_last_style(struct gui_tree *t, enum gui_style s)
{
    if (t->error[0] || t->count == 0 || s >= GS_COUNT) return;
    t->nodes[t->count - 1].style = s;
}
