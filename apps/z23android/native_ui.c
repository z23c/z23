/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "native_ui.h"
#include "base/cleanse.h"
#include "conversation.h"
#include "fleet.h"
#include "hosts.h"
#include "jni_util.h"
#include "shell.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static jobject root, status_view, result_view, prompt_view, invite_view, balance_view;
static jobject connection_view, transcript_view, fleet_view, receipt_view, details_view, notice_view;
static jobject voice_view, pair_view, hosts_view, sync_view, ops_view;
static jobject buttons[20];
static enum zapp_voice_state voice_state;
static bool details_open;
static enum zapp_reply_state reply_state;
static zapp_native_action callback;
static int pressed = -1;
static float down_x, down_y;
static char last_receipt[8192];
static bool voice_preview;
static char suggestion[96]; /* The question on the button, so a tap sends exactly what was shown. */
static const char *const actions[] = {"node_start", "node_stop", NULL, "chat", "scan", "fleet_preview", "fleet_join"};

static bool read_density(JNIEnv *env, jobject display)
{
    jclass cls = (*env)->GetObjectClass(env, display);
    jfieldID field = zj_clean(env) && cls ? (*env)->GetFieldID(env, cls, "density", "F") : NULL;
    if (!zj_clean(env) || !field) return false;
    jfloat density = (*env)->GetFloatField(env, display, field);
    if (!zj_clean(env) || density <= 0.0f || density >= 16.0f) return false;
    zj_set_density(density);
    return true;
}
static bool load_density(JNIEnv *env, jobject activity)
{
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject resources = zj_object_property(env, activity, "getResources", "()Landroid/content/res/Resources;");
    jobject display = resources ? zj_object_property(env, resources, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;") : NULL;
    bool ok = display && read_density(env, display);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
bool zapp_native_ui_package_preview(JNIEnv *env, jobject activity, bool *preview)
{
    if ((*env)->PushLocalFrame(env, 4) != JNI_OK) { (void)zj_clean(env); return false; }
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID get = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, "getPackageName", "()Ljava/lang/String;") : NULL;
    jstring package = zj_clean(env) && get ? (*env)->CallObjectMethod(env, activity, get) : NULL;
    const char *name = zj_clean(env) && package ? (*env)->GetStringUTFChars(env, package, NULL) : NULL;
    bool ok = zj_clean(env) && name;
    if (ok) *preview = !strncmp(name, "org.z23.voicepreview", strlen("org.z23.voicepreview"));
    if (name) (*env)->ReleaseStringUTFChars(env, package, name);
    ok = zj_clean(env) && ok;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static bool load_identity(JNIEnv *env, jobject activity)
{
    return zapp_native_ui_package_preview(env, activity, &voice_preview);
}
static bool line_spacing(JNIEnv *env, jobject view, float extra_dp)
{
    jmethodID set = zj_method(env, view, "setLineSpacing", "(FF)V");
    if (!set) return false;
    (*env)->CallVoidMethod(env, view, set, (jfloat)zj_dp(extra_dp), 1.0f);
    return zj_clean(env);
}
/* Shows HTML through android.text.Html.fromHtml; false leaves the view untouched. */
static bool html_text(JNIEnv *env, jobject view, const char *html)
{
    jclass cls = (*env)->FindClass(env, "android/text/Html");
    jmethodID from = zj_clean(env) && cls ?
        (*env)->GetStaticMethodID(env, cls, "fromHtml", "(Ljava/lang/String;I)Landroid/text/Spanned;") : NULL;
    jstring string = zj_clean(env) && from ? zj_string(env, html) : NULL;
    jobject spanned = string ? (*env)->CallStaticObjectMethod(env, cls, from, string, 0) : NULL;
    jmethodID set = zj_clean(env) && spanned ? zj_method(env, view, "setText", "(Ljava/lang/CharSequence;)V") : NULL;
    bool ok = set != NULL;
    if (ok) { (*env)->CallVoidMethod(env, view, set, spanned); ok = zj_clean(env); }
    if (spanned) (*env)->DeleteLocalRef(env, spanned);
    if (string) (*env)->DeleteLocalRef(env, string);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
/* Answer first: the newest answer in the default color, earlier text small and muted. */
static void show_transcript(JNIEnv *env, const struct zapp_view *view)
{
    static char html[2 * ZAPP_TEXT_CAP];
    if (!(zapp_transcript_html_pending(view->transcript, view->pending_question, html, sizeof(html)) && html_text(env, transcript_view, html)))
        (void)zj_text(env, transcript_view, view->transcript);
}
static bool small_label(const char *label, const jobject *save)
{
    return save == &status_view || save == &sync_view || save == &connection_view || save == &voice_view ||
        !strncmp(label, "Voice pairing:", 14);
}
static float label_size(const char *label, const jobject *save)
{
    if (!strcmp(label, "Fleet") || !strcmp(label, "Phone node") || !strcmp(label, "Type a question") ||
        !strcmp(label, "Fleet invitation")) return 18.0f;
    if (save == &transcript_view) return 18.0f;
    return small_label(label, save) ? 14.0f : 16.0f;
}
/* The Talk caption sits centered and muted in the bottom bar; the transcript gets open line spacing. */
static bool special_text(JNIEnv *env, jobject view, const jobject *save)
{
    if (save == &transcript_view) return line_spacing(env, view, 4.0f);
    return save != &voice_view || (zj_int_property(env, view, "setGravity", 1) &&
        zj_int_property(env, view, "setTextColor", (jint)0xff5f6662));
}
static bool add_text(JNIEnv *env, jobject layout, jobject activity, const char *label, jobject *save)
{
    jobject view = zj_widget(env, "android/widget/TextView", activity);
    bool ok = view && zj_typography(env, view, label_size(label, save), (jint)0xff262b2b) && zj_padding(env, view, 0, 4) &&
        zj_text(env, view, label) && special_text(env, view, save) &&
        zj_append(env, layout, view) && (!save || zj_keep(env, save, view));
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool primary_button(size_t i) { return i == 0 || i == 9 || i == 10 || i == 19; }
static bool style_button(JNIEnv *env, jobject view, size_t i)
{
    int min_height = zj_dp(i == 9 ? 64.0f : i == 15 ? 40.0f : 48.0f);
    return zj_typography(env, view, i == 15 || i == 8 ? 15.0f : 16.0f, primary_button(i) ? (jint)0xffffffff : (jint)0xff264a43) &&
        zj_bool_property(env, view, "setAllCaps", false) &&
        zj_int_property(env, view, "setMinHeight", min_height) &&
        zj_int_property(env, view, "setMinimumHeight", min_height) &&
        zj_padding(env, view, 16, 8);
}
/* Talk and Confirm are green pills, the suggestion a pale pill, More plain text, Start node a slab. */
static bool shape_button(JNIEnv *env, jobject view, size_t i)
{
    switch (i) {
    case 9: return zj_pill(env, view, (jint)0xff235e50, 32.0f) && zj_flatten(env, view) && zj_place(env, view, -1, -2, 0.0f, 0);
    case 10: case 19: return zj_pill(env, view, (jint)0xff235e50, 32.0f) && zj_flatten(env, view);
    case 15: return zj_pill(env, view, (jint)0xffe4ebe7, 20.0f) && zj_flatten(env, view) && zj_place(env, view, -2, -2, 0.0f, 8);
    case 8: return zj_int_property(env, view, "setBackgroundColor", 0);
    case 0: return zj_int_property(env, view, "setBackgroundColor", (jint)0xff235e50);
    default: return true;
    }
}
static bool add_button(JNIEnv *env, jobject layout, jobject activity, const char *label, size_t i)
{
    jobject view = zj_widget(env, "android/widget/Button", activity);
    bool ok = view && style_button(env, view, i) && zj_text(env, view, label) &&
        zj_append(env, layout, view) && zj_keep(env, &buttons[i], view) && shape_button(env, view, i);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
void zapp_native_ui_destroy(JNIEnv *env)
{
    zapp_shell_destroy(env);
    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); ++i) {
        if (buttons[i]) (*env)->DeleteGlobalRef(env, buttons[i]);
        buttons[i] = NULL;
    }
    jobject *views[] = {&root, &status_view, &balance_view, &result_view, &notice_view, &details_view, &prompt_view, &invite_view, &connection_view, &transcript_view, &fleet_view, &receipt_view, &voice_view, &pair_view, &hosts_view, &sync_view, &ops_view};
    for (size_t i = 0; i < sizeof(views) / sizeof(views[0]); ++i) {
        if (*views[i]) (*env)->DeleteGlobalRef(env, *views[i]);
        *views[i] = NULL;
    }
    suggestion[0] = 0;
    callback = NULL; pressed = -1; details_open = false; reply_state = ZAPP_REPLY_READY; last_receipt[0] = 0;
}
/* The main screen keeps the status and the conversation in the scrolling content; the voice controls
 * sit in a bottom bar that stays put while the conversation scrolls. */
static bool node_widgets(JNIEnv *env, jobject layout, jobject activity)
{
    return add_text(env, layout, activity, "", &status_view) &&
        add_button(env, layout, activity, "Start node", 0) &&
        add_text(env, layout, activity, "", &pair_view) &&
        add_button(env, layout, activity, "Accept pairing", 12) &&
        add_button(env, layout, activity, "Reject", 13) &&
        add_text(env, layout, activity, "", &notice_view) &&
        add_text(env, layout, activity, "", &transcript_view) &&
        add_button(env, layout, activity, "More", 8);
}
static bool bar_widgets(JNIEnv *env, jobject bar, jobject activity)
{
    return add_text(env, bar, activity, "Press Talk and ask anything.", &voice_view) &&
        add_button(env, bar, activity, "", 15) &&
        add_button(env, bar, activity, "Confirm", 10) &&
        add_button(env, bar, activity, "Talk", 9);
}
static bool ops_widgets(JNIEnv *env, jobject layout, jobject activity)
{
    return add_button(env, layout, activity, "Host", 16) && add_button(env, layout, activity, "Show errors", 17) &&
        add_button(env, layout, activity, "Restart node", 18) && add_text(env, layout, activity, "", &ops_view) &&
        add_button(env, layout, activity, "Confirm restart", 19);
}
static bool chat_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject receipt, jobject scroll)
{
    (void)invite; (void)receipt; (void)scroll;
    return !(!add_text(env, layout, activity, "Type a question", NULL) ||
        !zj_append(env, layout, prompt) || !zj_keep(env, &prompt_view, prompt) ||
        !add_button(env, layout, activity, "Send", 3) ||
        !add_text(env, layout, activity, "Not connected", &connection_view) ||
        !add_text(env, layout, activity, "Fleet", NULL) ||
        !add_text(env, layout, activity, "Ask by voice, or refresh to check every host.", &hosts_view) ||
        !add_button(env, layout, activity, "Refresh fleet", 14) ||
        !ops_widgets(env, layout, activity) ||
        !add_text(env, layout, activity, "Phone node", NULL) ||
        !add_text(env, layout, activity, "", &sync_view) ||
        !add_text(env, layout, activity, "Balance appears when your node is ready", &balance_view));
}
static bool detail_controls(JNIEnv *env, jobject layout, jobject activity)
{
    return add_button(env, layout, activity, "Stop node", 1) &&
        add_text(env, layout, activity, "Fleet invitation", NULL);
}
static bool fleet_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject receipt, jobject scroll)
{
    (void)prompt; (void)invite; (void)receipt; (void)scroll;
    return !(!detail_controls(env, layout, activity) ||
        !add_button(env, layout, activity, "Scan a code", 4) ||
        !zj_append(env, layout, invite) || !zj_keep(env, &invite_view, invite) ||
        !add_button(env, layout, activity, "Review invitation", 5) ||
        !add_button(env, layout, activity, "Join fleet", 6) ||
        !add_text(env, layout, activity, "", &fleet_view));
}
static bool finish_widgets(JNIEnv *env, jobject layout, jobject activity, jobject receipt)
{
    return zj_append(env, layout, receipt) && zj_keep(env, &receipt_view, receipt) &&
        add_text(env, layout, activity, "", &result_view);
}
static bool orient_layout(JNIEnv *env, jobject layout)
{
    jclass cls = (*env)->GetObjectClass(env, layout);
    jmethodID method = cls ? (*env)->GetMethodID(env, cls, "setOrientation", "(I)V") : NULL;
    if (!zj_clean(env) || !method) return false;
    (*env)->CallVoidMethod(env, layout, method, 1);
    return zj_clean(env);
}
static bool style_prompt(JNIEnv *env, jobject field)
{
    return zj_typography(env, field, 16.0f, (jint)0xff262b2b) &&
           zj_int_property(env, field, "setMinLines", 1) && zj_int_property(env, field, "setMaxLines", 4);
}
static bool prepare_layouts(JNIEnv *env, jobject layout, jobject details, jobject prompt, jobject invite, jobject receipt)
{
    return layout && prompt && invite && receipt && details &&
           orient_layout(env, layout) && orient_layout(env, details) &&
           zj_padding(env, layout, 20, 20) && style_prompt(env, prompt) && style_prompt(env, invite) &&
           zj_char_sequence(env, invite, "setHint", "Or paste an invitation");
}
/* The root stacks the scrolling content above a fixed bottom bar for the voice controls. */
static bool assemble_root(JNIEnv *env, jobject root_layout, jobject scroll, jobject bar)
{
    return root_layout && scroll && bar && orient_layout(env, root_layout) && orient_layout(env, bar) &&
           zj_bool_property(env, root_layout, "setFitsSystemWindows", true) &&
           zj_int_property(env, root_layout, "setBackgroundColor", (jint)0xfff7f5ef) &&
           zj_int_property(env, bar, "setBackgroundColor", (jint)0xfff7f5ef) &&
           zj_int_property(env, bar, "setGravity", 1) && zj_padding4(env, bar, 20, 8, 20, 16) &&
           zj_place(env, scroll, -1, 0, 1.0f, 0) && zj_append(env, root_layout, scroll) &&
           zj_append(env, root_layout, bar) && zj_keep(env, &root, root_layout);
}
static bool attach_details(JNIEnv *env, jobject details, jobject layout, jobject scroll)
{
    return zj_visible(env, details, false) && zj_append(env, layout, details) &&
           zj_keep(env, &details_view, details) && zj_append(env, scroll, layout);
}
static bool build_content(JNIEnv *env, jobject activity, jobject layout, jobject details, jobject bar)
{
    jobject prompt = zj_widget(env, "android/widget/EditText", activity);
    jobject invite = zj_widget(env, "android/widget/EditText", activity);
    jobject receipt = zj_widget(env, "android/widget/ImageView", activity);
    return prepare_layouts(env, layout, details, prompt, invite, receipt) &&
        node_widgets(env, layout, activity) && bar_widgets(env, bar, activity) &&
        chat_widgets(env, details, activity, prompt, invite, receipt, NULL) &&
        fleet_widgets(env, details, activity, prompt, invite, receipt, NULL) &&
        finish_widgets(env, details, activity, receipt);
}
static bool build_ui(JNIEnv *env, jobject activity)
{
    jobject scroll = zj_widget(env, "android/widget/ScrollView", activity);
    jobject layout = zj_widget(env, "android/widget/LinearLayout", activity);
    jobject details = zj_widget(env, "android/widget/LinearLayout", activity);
    jobject bar = zj_widget(env, "android/widget/LinearLayout", activity);
    jobject outer = zj_widget(env, "android/widget/LinearLayout", activity);
    return scroll && build_content(env, activity, layout, details, bar) &&
        attach_details(env, details, layout, scroll) && assemble_root(env, outer, scroll, bar);
}
bool zapp_native_ui_create(JNIEnv *env, jobject activity, zapp_native_action action)
{
    if (!env || !activity || !action || root) return false;
    if ((*env)->PushLocalFrame(env, 32) != JNI_OK) { (void)zj_clean(env); return false; }
    bool ok = load_density(env, activity) && load_identity(env, activity) &&
        build_ui(env, activity) && zapp_shell_create(env, activity, root, action, voice_preview);
    if (ok) callback = action;
    (void)zj_clean(env);
    (*env)->PopLocalFrame(env, NULL);
    if (!ok) zapp_native_ui_destroy(env);
    return ok;
}
static void emit_utf8(char *out, size_t *used, uint32_t cp)
{
                if (cp < 0x80) out[(*used)++] = (char)cp;
                else if (cp < 0x800) { out[(*used)++] = (char)(0xc0 | (cp >> 6)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
                else if (cp < 0x10000) { out[(*used)++] = (char)(0xe0 | (cp >> 12)); out[(*used)++] = (char)(0x80 | ((cp >> 6) & 63)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
                else { out[(*used)++] = (char)(0xf0 | (cp >> 18)); out[(*used)++] = (char)(0x80 | ((cp >> 12) & 63)); out[(*used)++] = (char)(0x80 | ((cp >> 6) & 63)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
}
static char *encode_prompt(const jchar *chars, jsize n)
{
    char *out = NULL;
    out = malloc((size_t)n * 3 + 1); size_t used = 0;
            if (out) for (jsize i = 0; i < n; ++i) {
                uint32_t cp = chars[i];
                if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < n && chars[i + 1] >= 0xdc00 && chars[i + 1] <= 0xdfff)
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (chars[++i] - 0xdc00);
                else if (!cp || (cp >= 0xd800 && cp <= 0xdfff)) { free(out); out = NULL; break; }
                emit_utf8(out, &used, cp);
            }
            if (out) out[used] = 0;
    return out;
}
static char *string_utf8(JNIEnv *env, jstring string)
{
    jsize n = (*env)->GetStringLength(env, string);
    const jchar *chars = (*env)->GetStringChars(env, string, NULL);
    char *out = NULL;
    if (zj_clean(env) && chars && n <= 16000) out = encode_prompt(chars, n);
    if (chars) (*env)->ReleaseStringChars(env, string, chars);
    return out;
}
static char *prompt_utf8(JNIEnv *env, jobject field)
{
    jclass cls = (*env)->GetObjectClass(env, field);
    if (!zj_clean(env) || !cls) return NULL;
    jmethodID get = (*env)->GetMethodID(env, cls, "getText", "()Landroid/text/Editable;");
    jobject editable = get ? (*env)->CallObjectMethod(env, field, get) : NULL;
    if (!zj_clean(env) || !editable) { (*env)->DeleteLocalRef(env, cls); return NULL; }
    jclass edit_class = (*env)->GetObjectClass(env, editable);
    jmethodID to_string = edit_class ? (*env)->GetMethodID(env, edit_class, "toString", "()Ljava/lang/String;") : NULL;
    jstring string = to_string ? (*env)->CallObjectMethod(env, editable, to_string) : NULL;
    char *out = NULL;
    if (zj_clean(env) && string) out = string_utf8(env, string);
    (void)zj_clean(env);
    if (string) (*env)->DeleteLocalRef(env, string);
    if (edit_class) (*env)->DeleteLocalRef(env, edit_class);
    (*env)->DeleteLocalRef(env, editable); (*env)->DeleteLocalRef(env, cls);
    return out;
}
static const char *voice_action(void)
{
    if (voice_state == ZAPP_VOICE_READY && reply_state != ZAPP_REPLY_READY) return "chat_cancel";
    return voice_state == ZAPP_VOICE_READY ? "voice_start" :
        voice_state == ZAPP_VOICE_RECORDING ? "voice_finish" : "voice_cancel";
}
static bool fixed_action(int index, const char **action, const char **arg)
{
    *arg = "";
    switch (index) {
    case 3: *action = "chat_cancel"; return reply_state != ZAPP_REPLY_READY;
    case 9: *action = voice_action(); return true;
    case 10: *action = "voice_confirm"; return true;
    case 12: *action = "pair_accept"; return true;
    case 13: *action = "pair_reject"; return true;
    case 14: *action = "fleet_hosts"; *arg = "refresh"; return true;
    case 15: *action = "chat"; *arg = suggestion; return suggestion[0] != 0;
    case 16: *action = "ops_next"; return true;
    case 17: *action = "ops_errors"; return true;
    case 18: *action = "ops_restart"; return true;
    case 19: *action = "ops_confirm"; return true;
    default: return false;
    }
}
static void text_action(JNIEnv *env, const char *action, jobject field)
{
    char *value = prompt_utf8(env, field);
    if (!value) return;
    callback(action, value);
    memory_cleanse(value, strlen(value)); free(value);
}
static void input_up(JNIEnv *env, float x, float y)
{
    int index = pressed; pressed = -1;
    if (index < 0 || !zj_hit(env, buttons[index], x, y)) return;
    if (index == 8) {
        bool next = !details_open;
        if (zj_visible(env, details_view, next)) { details_open = next; (void)zj_text(env, buttons[8], next ? "Less" : "More"); }
        return;
    }
    const char *action, *arg;
    if (fixed_action(index, &action, &arg)) { callback(action, arg); return; }
    if (index >= (int)(sizeof(actions) / sizeof(*actions)) || !actions[index]) return;
    if (index == 3 || index == 5) { text_action(env, actions[index], index == 3 ? prompt_view : invite_view); return; }
    callback(actions[index], "");
}
static void assistant_touch(JNIEnv *env, const AInputEvent *event)
{
    int32_t action = AMotionEvent_getAction(event) & AMOTION_EVENT_ACTION_MASK;
    float x = AMotionEvent_getX(event, 0), y = AMotionEvent_getY(event, 0);
    if (action == AMOTION_EVENT_ACTION_DOWN) {
        pressed = -1; down_x = x; down_y = y;
        for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); ++i)
            if (buttons[i] && zj_hit(env, buttons[i], x, y)) { pressed = (int)i; break; }
    } else if (action == AMOTION_EVENT_ACTION_MOVE) {
        if (x - down_x > 20 || down_x - x > 20 || y - down_y > 20 || down_y - y > 20) pressed = -1;
    } else if (action == AMOTION_EVENT_ACTION_CANCEL) pressed = -1;
    else if (action == AMOTION_EVENT_ACTION_UP) input_up(env, x, y);
}
bool zapp_native_ui_input(JNIEnv *env, const AInputEvent *event)
{
    bool assistant = zapp_shell_assistant();
    if (zapp_shell_input(env, event)) return true;
    if (callback && event && assistant && AInputEvent_getType(event) == AINPUT_EVENT_TYPE_MOTION) assistant_touch(env, event);
    return false;
}
void zapp_native_ui_update(JNIEnv *env, const char *status, const char *output)
{
    if (voice_view && status) (void)zj_text(env, voice_view, status);
    if (notice_view && output) { (void)zj_text(env, notice_view, output); (void)zj_visible(env, notice_view, true); }
    if (output) zapp_shell_notice(env, output);
}


void zapp_native_ui_preview(JNIEnv *env, const unsigned char *bmp, size_t len)
{ zapp_shell_preview(env, bmp, len); }

static void receipt_qr(JNIEnv *env, const char *value)
{
    if (!strcmp(last_receipt, value)) return;
    last_receipt[0] = 0;
    if (!*value) { (void)zj_bitmap(env, receipt_view, NULL, 0); return; }
    size_t size = 0;
    unsigned char *bmp = zapp_fleet_qr_bmp(value, &size);
    bool shown = bmp && zj_bitmap(env, receipt_view, bmp, size);
    free(bmp);
    if (shown && strlen(value) < sizeof(last_receipt)) memcpy(last_receipt, value, strlen(value) + 1);
    else (void)zj_bitmap(env, receipt_view, NULL, 0);
}
static const char *talk_label(enum zapp_voice_state voice, enum zapp_reply_state reply)
{
    if (voice == ZAPP_VOICE_READY && reply != ZAPP_REPLY_READY) return "Stop";
    return voice == ZAPP_VOICE_READY ? "Talk" : voice == ZAPP_VOICE_RECORDING ? "Done talking" :
        voice == ZAPP_VOICE_OBSERVING ? "Stop" : voice == ZAPP_VOICE_PLAYING ? "Stop speaking" : "Cancel";
}
/* While a question is answered the caption says so, whatever the last voice stage reported. */
static const char *caption(const struct zapp_view *view)
{
    if (view->reply_state == ZAPP_REPLY_WAITING || view->voice_state == ZAPP_VOICE_OBSERVING) return "Thinking…";
    return view->voice_status[0] ? view->voice_status : "Press Talk and ask anything.";
}
/* The suggestion shows while voice is idle, nothing awaits confirmation and no reply is pending. */
static bool suggestion_shown(const struct zapp_view *view)
{
    return view->suggestion[0] && !view->voice_proposal[0] &&
        view->voice_state == ZAPP_VOICE_READY && view->reply_state == ZAPP_REPLY_READY;
}
/* A voice status line stays above the suggestion; only the default hint gives way to it. */
static void render_voice(JNIEnv *env, const struct zapp_view *view)
{
    if (buttons[9]) (void)zj_text(env, buttons[9], talk_label(voice_state, reply_state));
    bool offer = suggestion_shown(view);
    snprintf(suggestion, sizeof(suggestion), "%s", offer ? view->suggestion : "");
    if (buttons[15]) { (void)zj_text(env, buttons[15], suggestion); (void)zj_visible(env, buttons[15], offer); }
    if (voice_view) (void)zj_visible(env, voice_view, view->voice_status[0] || !offer);
    if (voice_view) (void)zj_text(env, voice_view, caption(view));
    if (buttons[10]) {
        (void)zj_text(env, buttons[10], !strcmp(view->voice_proposal, "node_start") ? "Confirm start" : "Confirm stop");
        (void)zj_visible(env, buttons[10], view->voice_proposal[0] && !view->busy);
    }
}
static void render_node(JNIEnv *env, const struct zapp_view *view)
{
    const char *send_label = reply_state == ZAPP_REPLY_WAITING ? "Stop reply" :
        reply_state == ZAPP_REPLY_CANCELLING ? "Stopping…" : "Send";
    if (buttons[3]) (void)zj_text(env, buttons[3], send_label);
    char status[1100];
    snprintf(status, sizeof(status), "%s%s", view->sync_status[0] ? view->sync_status : "Sync status unknown",
             view->busy ? "\nWorking…" : "");
    (void)zj_text(env, sync_view, voice_preview ? "The preview app does not run a node." : status);
    (void)zj_visible(env, balance_view, !voice_preview);
    char balance[600];
    snprintf(balance, sizeof(balance), "%s%s", view->balance_stale ? "Last known:\n" : "",
             view->balance[0] ? view->balance : "Balance appears when your node is ready");
    (void)zj_text(env, balance_view, balance);
    (void)zj_text(env, connection_view, view->connection[0] ? view->connection : "Connect a laptop to use chat.");
    show_transcript(env, view);
    (void)zj_visible(env, transcript_view, view->transcript[0] || view->pending_question[0]);
}
/* Two lines at the top: the phone node and, while a laptop host is paired, the fleet headline. */
static void render_status(JNIEnv *env, const struct zapp_view *view)
{
    char fleet[160], status[320], node[96];
    zapp_fleet_line(view->fleet_status, view->fleet_stale, view->fleet_paired, fleet, sizeof(fleet));
    snprintf(status, sizeof(status), "%s%s%s", voice_preview ?
             "Preview · separate from your main node" :
             zapp_paced_line(view->pace, view->node_running || view->node_process_running, view->node_line, node, sizeof(node)), fleet[0] ? "\n" : "", fleet);
    (void)zj_text(env, status_view, status);
    bool running = view->node_running || view->node_process_running;
    bool shown = !voice_preview && !view->busy;
    if (buttons[0]) (void)zj_visible(env, buttons[0], shown && !running);
    /* Stop node also clears a saved Start node choice when that node has exited on its own. */
    if (buttons[1]) (void)zj_visible(env, buttons[1], shown && (running || view->node_wanted));
}
/* The host controls show only while a laptop host is paired and has reported a host; Confirm restart
 * only for a plan the host returned. */
static void render_ops(JNIEnv *env, const struct zapp_view *view)
{
    char label[40];
    bool shown = view->fleet_paired && view->ops_host[0] && !voice_preview;
    snprintf(label, sizeof(label), "Host: %s", view->ops_host);
    if (buttons[16]) (void)zj_text(env, buttons[16], label);
    for (int i = 16; i <= 18; ++i) if (buttons[i]) (void)zj_visible(env, buttons[i], shown);
    if (buttons[19]) (void)zj_visible(env, buttons[19], shown && view->ops_plan[0] && !view->busy);
    if (ops_view) { (void)zj_text(env, ops_view, view->ops_text); (void)zj_visible(env, ops_view, shown && view->ops_text[0]); }
}
static void render_fleet(JNIEnv *env, const struct zapp_view *view)
{
    char fleet[10272], pairing[160];
    /* The headline is already at the top of the screen; More lists the hosts under it. */
    const char *rows = strchr(view->fleet_status, '\n');
    if (rows) rows += strspn(rows, "\n");
    if (view->fleet_status[0]) {
        snprintf(fleet, sizeof(fleet), "%s%s", view->fleet_stale ? "No current fleet report. Last report:\n\n" : "",
                 view->fleet_stale || !rows ? view->fleet_status : rows);
        (void)zj_text(env, hosts_view, fleet);
    }
    snprintf(fleet, sizeof(fleet), "%s%s%s", view->fleet_preview,
             view->fleet_receipt[0] ? "\nReceipt: " : "", view->fleet_receipt);
    snprintf(pairing, sizeof(pairing), "Your laptop offers private voice and fleet control. "
             "Accept only if the laptop shows code %s.", view->pair_code);
    (void)zj_text(env, pair_view, pairing);
    (void)zj_visible(env, pair_view, view->pair_offer[0] != 0);
    for (int i = 12; i <= 13; ++i) if (buttons[i]) (void)zj_visible(env, buttons[i], view->pair_offer[0] && !view->busy);
    (void)zj_text(env, fleet_view, fleet);
    (void)zj_text(env, notice_view, view->notice);
    (void)zj_visible(env, notice_view, view->notice[0] != 0);
    (void)zj_text(env, result_view, view->result);
}
void zapp_native_ui_render(JNIEnv *env, const struct zapp_view *view)
{
    if (!env || !view) return;
    reply_state = view->reply_state;
    voice_state = view->voice_state;
    render_voice(env, view);
    render_status(env, view);
    render_node(env, view);
    render_fleet(env, view);
    render_ops(env, view);
    receipt_qr(env, view->fleet_receipt);
    zapp_shell_render(env, view);
}
void zapp_native_ui_resume(JNIEnv *env) { zapp_shell_resume(env); }
void zapp_native_ui_focus(JNIEnv *env) { zapp_shell_immersive(env); }
void zapp_native_ui_open_details(JNIEnv *env)
{
    if (details_open || !details_view || !zj_visible(env, details_view, true)) return;
    details_open = true;
    if (buttons[8]) (void)zj_text(env, buttons[8], "Less");
}
