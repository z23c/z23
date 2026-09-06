/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * /install.sh — serves platform/packaging/install/install_from_source.sh,
 * the honest source-build front door: `curl -fsSL https://<site>/install.sh
 * | sh` builds a node from source and downloads no binary
 * (docs/work/BOOTSTRAP_PLAN.md:10). The HTTPS front door's root also serves
 * this body to a curl/Wget client asking for "/" (see
 * https_root_wants_install_script() in core/modules/net/src/https_server.c) so the
 * documented one-liner works without the /install.sh suffix too.
 *
 * The script is embedded at build time (install_script_gen.h, generated
 * from the .sh source by tools/gen_templates.c --single-text) — never read
 * from disk at request time. This handler's only job is substituting the
 * script's `Z23_PIN="__Z23_PIN__"` placeholder with a commit this build can
 * name, or leaving it empty. */

#include "views/install_sh_view.h"
#include "views/install_script_gen.h"
#include "util/clientversion.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define INSTALL_SH_PLACEHOLDER "__Z23_PIN__"

/* zcl_build_commit() answers a different question on purpose
 * (platform/modules/util/include/util/clientversion.h): Git commit ids are
 * deliberately NOT baked into the sovereign executable, so every build
 * currently reports the literal "external". Any value that is not a real
 * commit trace is treated as "unknown" here, and the script is served with
 * its pin empty — it says so and falls back to main itself. */
static bool install_sh_pin_is_real(const char *commit)
{
    return commit && commit[0] != '\0' &&
          strcmp(commit, "external") != 0 &&
          strcmp(commit, "unknown") != 0;
}

/* Copy `src` into `dst` (capacity `dst_max`, NUL-terminated) with every
 * occurrence of the pin placeholder replaced by `pin`. Returns the written
 * length, or 0 if it would not fit. */
static size_t install_sh_render(const char *src, const char *pin,
                                char *dst, size_t dst_max)
{
    const size_t placeholder_len = sizeof(INSTALL_SH_PLACEHOLDER) - 1;
    const size_t pin_len = strlen(pin);
    size_t out = 0;

    for (const char *p = src; *p != '\0';) {
        if (strncmp(p, INSTALL_SH_PLACEHOLDER, placeholder_len) == 0) {
            if (out + pin_len >= dst_max) return 0;
            memcpy(dst + out, pin, pin_len);
            out += pin_len;
            p += placeholder_len;
        } else {
            if (out + 1 >= dst_max) return 0;
            dst[out++] = *p++;
        }
    }
    dst[out] = '\0';
    return out;
}

size_t install_sh_handle_request(const char *method, const char *path,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *response, size_t response_max)
{
    (void)path;
    (void)body;
    (void)body_len;
    if (!method || !response || response_max < 4096)
        return 0;

    const bool head_only = strcmp(method, "HEAD") == 0;
    if (strcmp(method, "GET") != 0 && !head_only) {
        static const char denied[] = "Only GET/HEAD is supported.\n";
        return (size_t)snprintf((char *)response, response_max,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n%s",
            sizeof(denied) - 1, denied);
    }

    const char *pin = install_sh_pin_is_real(zcl_build_commit())
                          ? zcl_build_commit()
                          : "";
    char script[8192];
    size_t script_len =
        install_sh_render(INSTALL_FROM_SOURCE_SH, pin, script, sizeof(script));
    if (script_len == 0)
        return 0;

    char header[256];
    int hdr_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/x-shellscript; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        script_len);
    if (hdr_len <= 0 || (size_t)hdr_len >= sizeof(header))
        return 0;

    size_t body_out = head_only ? 0 : script_len;
    if ((size_t)hdr_len + body_out > response_max)
        return 0;

    memcpy(response, header, (size_t)hdr_len);
    size_t total = (size_t)hdr_len;
    if (!head_only) {
        memcpy(response + total, script, script_len);
        total += script_len;
    }
    return total;
}
