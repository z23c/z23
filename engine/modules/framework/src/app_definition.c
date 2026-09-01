/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fail-closed compiler for the small, declarative built-in App language. */

#include "framework/app_definition.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum app_definition_error {
    APP_DEF_INVALID_ARGUMENT = -3300,
    APP_DEF_SYNTAX = -3302,
    APP_DEF_LIMIT = -3303,
    APP_DEF_SEMANTIC = -3304,
};

struct app_definition_parser {
    const char *source;
    size_t source_len;
    size_t offset;
    size_t line;
    size_t directive_count;
};

struct app_definition_compile {
    struct app_definition_parser parser;
    struct zcl_app_definition_v1 definition;
    bool app_seen;
};

struct capability_spec {
    const char *name;
    uint64_t bit;
};

static const struct capability_spec g_capabilities[] = {
    { "CHAIN_READ", ZCL_APP_CAP_CHAIN_READ },
    { "SIGNED_EVENTS", ZCL_APP_CAP_SIGNED_EVENTS },
    { "RESIDENT_STATE", ZCL_APP_CAP_RESIDENT_STATE },
    { "WEB_ROUTES", ZCL_APP_CAP_WEB_ROUTES },
    { "ONION_BINDING", ZCL_APP_CAP_ONION_BINDING },
    { "ZNAM_BINDING", ZCL_APP_CAP_ZNAM_BINDING },
    { "P2P_TOPICS", ZCL_APP_CAP_P2P_TOPICS },
    { "WALLET_REQUESTS", ZCL_APP_CAP_WALLET_REQUESTS },
    { "SCHEDULED_JOBS", ZCL_APP_CAP_SCHEDULED_JOBS },
    { "CLOCK", ZCL_APP_CAP_CLOCK },
    { "RANDOM", ZCL_APP_CAP_RANDOM },
};

static struct zcl_result parser_error(struct app_definition_parser *parser,
                                      int code,
                                      const char *fmt,
                                      ...)
{
    char detail[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    return zcl_result_make(code, __FILE__, __LINE__,
                           "app definition line %zu: %s",
                           parser ? parser->line : 0, detail);
}

static bool ascii_lower(unsigned char c)
{
    return c >= 'a' && c <= 'z';
}

static bool ascii_upper(unsigned char c)
{
    return c >= 'A' && c <= 'Z';
}

static bool ascii_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static bool ascii_alnum_lower(unsigned char c)
{
    return ascii_lower(c) || ascii_digit(c);
}

bool zcl_app_definition_id_valid_v1(const char *value)
{
    if (!value)
        return false;
    const char *end = memchr(value, '\0', ZCL_APP_ID_MAX + 1u);
    if (!end)
        return false;
    size_t len = (size_t)(end - value);
    if (len == 0 || len > ZCL_APP_ID_MAX || !ascii_lower((unsigned char)value[0]) ||
        !ascii_alnum_lower((unsigned char)value[len - 1]))
        return false;
    for (size_t i = 1; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!ascii_alnum_lower(c) && c != '-')
            return false;
        if (c == '-' && value[i - 1] == '-')
            return false;
    }
    return true;
}

static bool lower_name_valid(const char *value, size_t max_len, bool underscore)
{
    size_t len = value ? strlen(value) : 0;
    if (len == 0 || len > max_len || !ascii_lower((unsigned char)value[0]) ||
        !ascii_alnum_lower((unsigned char)value[len - 1]))
        return false;
    for (size_t i = 1; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!ascii_alnum_lower(c) && (!underscore || c != '_'))
            return false;
        if (c == '_' && value[i - 1] == '_')
            return false;
    }
    return true;
}

static bool topic_valid(const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len == 0 || len > ZCL_APP_TOPIC_MAX ||
        !ascii_alnum_lower((unsigned char)value[0]) ||
        !ascii_alnum_lower((unsigned char)value[len - 1]))
        return false;
    for (size_t i = 1; i + 1 < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!ascii_alnum_lower(c) && c != '.' && c != '-' && c != '_')
            return false;
        if ((c == '.' || c == '-' || c == '_') &&
            (value[i - 1] == '.' || value[i - 1] == '-' || value[i - 1] == '_'))
            return false;
    }
    return true;
}

static bool mount_valid(const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len == 0 || len > ZCL_APP_ROUTE_MAX || value[0] != '/')
        return false;
    if (len == 1)
        return true;
    if (value[len - 1] == '/')
        return false;
    size_t segment_start = 1;
    for (size_t i = 1; i <= len; i++) {
        if (i == len || value[i] == '/') {
            size_t segment_len = i - segment_start;
            if (segment_len == 0 ||
                (segment_len == 1 && value[segment_start] == '.') ||
                (segment_len == 2 && value[segment_start] == '.' &&
                 value[segment_start + 1] == '.'))
                return false;
            segment_start = i + 1;
            continue;
        }
        unsigned char c = (unsigned char)value[i];
        if (!ascii_alnum_lower(c) && c != '-' && c != '_')
            return false;
    }
    return true;
}

static bool znam_valid(const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len == 0 || len > ZCL_APP_DEFINITION_ZNAM_MAX ||
        !ascii_alnum_lower((unsigned char)value[0]) ||
        !ascii_alnum_lower((unsigned char)value[len - 1]))
        return false;
    for (size_t i = 1; i + 1 < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!ascii_alnum_lower(c) && c != '-')
            return false;
        if (c == '-' && value[i - 1] == '-')
            return false;
    }
    return true;
}

static bool display_name_valid(const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len == 0 || len > ZCL_APP_DEFINITION_DISPLAY_MAX ||
        value[0] == ' ' || value[len - 1] == ' ')
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c < 0x20 || c > 0x7e)
            return false;
    }
    return true;
}

static bool semver_component(const char **cursor)
{
    const char *p = *cursor;
    if (!ascii_digit((unsigned char)*p))
        return false;
    if (*p == '0' && ascii_digit((unsigned char)p[1]))
        return false;
    uint32_t value = 0;
    while (ascii_digit((unsigned char)*p)) {
        uint32_t digit = (uint32_t)(*p - '0');
        if (value > (65535u - digit) / 10u)
            return false;
        value = value * 10u + digit;
        p++;
    }
    *cursor = p;
    return true;
}

static bool version_valid(const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len == 0 || len > ZCL_APP_DEFINITION_VERSION_MAX)
        return false;
    const char *cursor = value;
    for (unsigned int component = 0; component < 3; component++) {
        if (!semver_component(&cursor))
            return false;
        if (component < 2) {
            if (*cursor != '.')
                return false;
            cursor++;
        }
    }
    return *cursor == '\0';
}

static void parser_advance(struct app_definition_parser *parser)
{
    if (parser->offset < parser->source_len) {
        if (parser->source[parser->offset] == '\n')
            parser->line++;
        parser->offset++;
    }
}

static struct zcl_result parser_skip_trivia(struct app_definition_parser *parser)
{
    while (parser->offset < parser->source_len) {
        unsigned char c = (unsigned char)parser->source[parser->offset];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            parser_advance(parser);
            continue;
        }
        if (c != '/' || parser->offset + 1 >= parser->source_len)
            return ZCL_OK;
        char next = parser->source[parser->offset + 1];
        if (next == '/') {
            parser_advance(parser);
            parser_advance(parser);
            while (parser->offset < parser->source_len &&
                   parser->source[parser->offset] != '\n')
                parser_advance(parser);
            continue;
        }
        if (next != '*')
            return ZCL_OK;
        size_t start_line = parser->line;
        parser_advance(parser);
        parser_advance(parser);
        bool closed = false;
        while (parser->offset < parser->source_len) {
            if (parser->source[parser->offset] == '*' &&
                parser->offset + 1 < parser->source_len &&
                parser->source[parser->offset + 1] == '/') {
                parser_advance(parser);
                parser_advance(parser);
                closed = true;
                break;
            }
            parser_advance(parser);
        }
        if (!closed)
            return parser_error(parser, APP_DEF_SYNTAX,
                                "unterminated comment opened on line %zu",
                                start_line);
    }
    return ZCL_OK;
}

static struct zcl_result parser_identifier(struct app_definition_parser *parser,
                                           char *out,
                                           size_t out_size)
{
    struct zcl_result result = parser_skip_trivia(parser);
    if (!result.ok)
        return result;
    if (parser->offset >= parser->source_len)
        return parser_error(parser, APP_DEF_SYNTAX,
                            "expected directive, found end of input");
    unsigned char first = (unsigned char)parser->source[parser->offset];
    if (!ascii_lower(first) && !ascii_upper(first) && first != '_')
        return parser_error(parser, APP_DEF_SYNTAX,
                            "unexpected byte 0x%02x (trailing junk)", first);
    size_t start = parser->offset;
    parser_advance(parser);
    while (parser->offset < parser->source_len) {
        unsigned char c = (unsigned char)parser->source[parser->offset];
        if (!ascii_lower(c) && !ascii_upper(c) && !ascii_digit(c) && c != '_')
            break;
        parser_advance(parser);
    }
    size_t len = parser->offset - start;
    if (len >= out_size)
        return parser_error(parser, APP_DEF_LIMIT, "directive token is too long");
    memcpy(out, parser->source + start, len);
    out[len] = '\0';
    return ZCL_OK;
}

static struct zcl_result parser_expect(struct app_definition_parser *parser,
                                       char expected)
{
    struct zcl_result result = parser_skip_trivia(parser);
    if (!result.ok)
        return result;
    if (parser->offset >= parser->source_len ||
        parser->source[parser->offset] != expected)
        return parser_error(parser, APP_DEF_SYNTAX, "expected '%c'", expected);
    parser_advance(parser);
    return ZCL_OK;
}

static struct zcl_result parser_string(struct app_definition_parser *parser,
                                       char *out,
                                       size_t out_size)
{
    struct zcl_result result = parser_skip_trivia(parser);
    if (!result.ok)
        return result;
    if (parser->offset >= parser->source_len ||
        parser->source[parser->offset] != '"')
        return parser_error(parser, APP_DEF_SYNTAX, "expected quoted string");
    parser_advance(parser);
    size_t len = 0;
    while (parser->offset < parser->source_len &&
           parser->source[parser->offset] != '"') {
        unsigned char c = (unsigned char)parser->source[parser->offset];
        if (c == '\\' || c < 0x20 || c > 0x7e)
            return parser_error(parser, APP_DEF_SYNTAX,
                                "string contains non-canonical byte 0x%02x", c);
        if (len + 1 >= out_size)
            return parser_error(parser, APP_DEF_LIMIT, "string is too long");
        out[len++] = (char)c;
        parser_advance(parser);
    }
    if (parser->offset >= parser->source_len)
        return parser_error(parser, APP_DEF_SYNTAX, "unterminated string");
    parser_advance(parser);
    out[len] = '\0';
    return ZCL_OK;
}

static struct zcl_result parser_u32(struct app_definition_parser *parser,
                                    uint32_t *out)
{
    struct zcl_result result = parser_skip_trivia(parser);
    if (!result.ok)
        return result;
    if (parser->offset >= parser->source_len ||
        !ascii_digit((unsigned char)parser->source[parser->offset]))
        return parser_error(parser, APP_DEF_SYNTAX,
                            "expected unsigned decimal integer");
    size_t start = parser->offset;
    uint32_t value = 0;
    while (parser->offset < parser->source_len &&
           ascii_digit((unsigned char)parser->source[parser->offset])) {
        uint32_t digit =
            (uint32_t)(parser->source[parser->offset] - '0');
        if (value > (UINT32_MAX - digit) / 10u)
            return parser_error(parser, APP_DEF_LIMIT, "integer exceeds uint32");
        value = value * 10u + digit;
        parser_advance(parser);
    }
    if (parser->offset - start > 1 && parser->source[start] == '0')
        return parser_error(parser, APP_DEF_SYNTAX,
                            "integer has a non-canonical leading zero");
    *out = value;
    return ZCL_OK;
}

static struct zcl_result parse_app(struct app_definition_compile *compile,
                                   const char *expected_app_id)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->app_seen)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "duplicate ZCL_APP directive");
    if (parser->directive_count != 1)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "ZCL_APP must be the first directive");
    char app_id[ZCL_APP_ID_MAX + 1];
    char display[ZCL_APP_DEFINITION_DISPLAY_MAX + 1];
    char version[ZCL_APP_DEFINITION_VERSION_MAX + 1];
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_string(parser, app_id, sizeof(app_id));
    if (!result.ok) return result;
    result = parser_expect(parser, ',');
    if (!result.ok) return result;
    result = parser_string(parser, display, sizeof(display));
    if (!result.ok) return result;
    result = parser_expect(parser, ',');
    if (!result.ok) return result;
    result = parser_string(parser, version, sizeof(version));
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (!zcl_app_definition_id_valid_v1(app_id))
        return parser_error(parser, APP_DEF_SEMANTIC, "invalid app id '%s'", app_id);
    if (strcmp(app_id, expected_app_id) != 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "declared app id '%s' does not match path id '%s'",
                            app_id, expected_app_id);
    if (!display_name_valid(display))
        return parser_error(parser, APP_DEF_SEMANTIC, "invalid display name");
    if (!version_valid(version))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "invalid semantic version '%s'", version);
    snprintf(compile->definition.app_id, sizeof(compile->definition.app_id),
             "%s", app_id);
    snprintf(compile->definition.display_name,
             sizeof(compile->definition.display_name), "%s", display);
    snprintf(compile->definition.app_version,
             sizeof(compile->definition.app_version), "%s", version);
    compile->app_seen = true;
    return ZCL_OK;
}

static struct zcl_result parse_capability(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    char name[64];
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_identifier(parser, name, sizeof(name));
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    uint64_t bit = 0;
    for (size_t i = 0; i < sizeof(g_capabilities) / sizeof(g_capabilities[0]); i++) {
        if (strcmp(name, g_capabilities[i].name) == 0) {
            bit = g_capabilities[i].bit;
            break;
        }
    }
    if (bit == 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "unknown capability '%s'", name);
    if ((compile->definition.required_capabilities & bit) != 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "duplicate capability '%s'", name);
    compile->definition.required_capabilities |= bit;
    return ZCL_OK;
}

static struct zcl_result parse_resource(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->definition.resource_count >= ZCL_APP_DEFINITION_RESOURCE_MAX)
        return parser_error(parser, APP_DEF_LIMIT, "too many resources");
    char name[ZCL_APP_DEFINITION_RESOURCE_NAME_MAX + 1];
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_string(parser, name, sizeof(name));
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (!lower_name_valid(name, ZCL_APP_DEFINITION_RESOURCE_NAME_MAX, true))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "invalid resource name '%s'", name);
    for (size_t i = 0; i < compile->definition.resource_count; i++) {
        if (strcmp(name, compile->definition.resources[i].name) == 0)
            return parser_error(parser, APP_DEF_SEMANTIC,
                                "duplicate resource '%s'", name);
    }
    snprintf(compile->definition.resources[compile->definition.resource_count++].name,
             sizeof(compile->definition.resources[0].name), "%s", name);
    return ZCL_OK;
}

static struct zcl_result parse_topic(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->definition.topic_count >= ZCL_APP_DEFINITION_TOPIC_MAX)
        return parser_error(parser, APP_DEF_LIMIT, "too many topics");
    char name[ZCL_APP_TOPIC_MAX + 1];
    uint32_t wire_version = 0, max_event_bytes = 0;
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_string(parser, name, sizeof(name));
    if (!result.ok) return result;
    result = parser_expect(parser, ',');
    if (!result.ok) return result;
    result = parser_u32(parser, &wire_version);
    if (!result.ok) return result;
    result = parser_expect(parser, ',');
    if (!result.ok) return result;
    result = parser_u32(parser, &max_event_bytes);
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (!topic_valid(name) || wire_version == 0 || max_event_bytes == 0 ||
        max_event_bytes > ZCL_APP_DEFINITION_EVENT_BYTES_MAX)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "invalid topic declaration '%s'", name);
    for (size_t i = 0; i < compile->definition.topic_count; i++) {
        if (strcmp(name, compile->definition.topics[i].name) == 0)
            return parser_error(parser, APP_DEF_SEMANTIC,
                                "duplicate topic '%s'", name);
    }
    struct zcl_app_definition_topic_v1 *topic =
        &compile->definition.topics[compile->definition.topic_count++];
    snprintf(topic->name, sizeof(topic->name), "%s", name);
    topic->wire_version = wire_version;
    topic->max_event_bytes = max_event_bytes;
    return ZCL_OK;
}

static struct zcl_result parse_mount(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->definition.mount_count >= ZCL_APP_DEFINITION_MOUNT_MAX)
        return parser_error(parser, APP_DEF_LIMIT, "too many web mounts");
    char path[ZCL_APP_ROUTE_MAX + 1];
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_string(parser, path, sizeof(path));
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (!mount_valid(path))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "invalid web mount '%s'", path);
    for (size_t i = 0; i < compile->definition.mount_count; i++) {
        if (strcmp(path, compile->definition.mounts[i].path) == 0)
            return parser_error(parser, APP_DEF_SEMANTIC,
                                "duplicate web mount '%s'", path);
    }
    snprintf(compile->definition.mounts[compile->definition.mount_count++].path,
             sizeof(compile->definition.mounts[0].path), "%s", path);
    return ZCL_OK;
}

static struct zcl_result parse_onion(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->definition.onion_declared)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "duplicate ZCL_APP_ONION directive");
    char value[16];
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_identifier(parser, value, sizeof(value));
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (strcmp(value, "true") != 0 && strcmp(value, "false") != 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "onion binding must be true or false");
    compile->definition.onion_declared = true;
    compile->definition.onion_enabled = strcmp(value, "true") == 0;
    return ZCL_OK;
}

static struct zcl_result parse_znam(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->definition.znam_declared)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "duplicate ZCL_APP_ZNAM directive");
    char name[ZCL_APP_DEFINITION_ZNAM_MAX + 1];
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_string(parser, name, sizeof(name));
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (!znam_valid(name))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "invalid ZNAM binding '%s'", name);
    compile->definition.znam_declared = true;
    snprintf(compile->definition.znam, sizeof(compile->definition.znam),
             "%s", name);
    return ZCL_OK;
}

static struct zcl_result parse_state_schema(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->definition.state_schema_declared)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "duplicate ZCL_APP_STATE_SCHEMA directive");
    uint32_t version = 0;
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_u32(parser, &version);
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (version == 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "state schema version must be positive");
    compile->definition.state_schema_declared = true;
    compile->definition.state_schema_version = version;
    return ZCL_OK;
}

static struct zcl_result parse_sim(struct app_definition_compile *compile)
{
    struct app_definition_parser *parser = &compile->parser;
    if (compile->definition.simulation_count >= ZCL_APP_DEFINITION_SIM_MAX)
        return parser_error(parser, APP_DEF_LIMIT, "too many simulations");
    char name[ZCL_APP_DEFINITION_SIM_NAME_MAX + 1];
    struct zcl_result result = parser_expect(parser, '(');
    if (!result.ok) return result;
    result = parser_string(parser, name, sizeof(name));
    if (!result.ok) return result;
    result = parser_expect(parser, ')');
    if (!result.ok) return result;
    if (!lower_name_valid(name, ZCL_APP_DEFINITION_SIM_NAME_MAX, true))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "invalid simulation name '%s'", name);
    for (size_t i = 0; i < compile->definition.simulation_count; i++) {
        if (strcmp(name, compile->definition.simulations[i].name) == 0)
            return parser_error(parser, APP_DEF_SEMANTIC,
                                "duplicate simulation '%s'", name);
    }
    snprintf(compile->definition.simulations[
                 compile->definition.simulation_count++].name,
             sizeof(compile->definition.simulations[0].name), "%s", name);
    return ZCL_OK;
}

static struct zcl_result parse_directive(struct app_definition_compile *compile,
                                         const char *expected_app_id,
                                         const char *directive)
{
    if (strcmp(directive, "ZCL_APP") == 0)
        return parse_app(compile, expected_app_id);
    if (!compile->app_seen)
        return parser_error(&compile->parser, APP_DEF_SEMANTIC,
                            "ZCL_APP must be the first directive");
    if (strcmp(directive, "ZCL_APP_CAPABILITY") == 0)
        return parse_capability(compile);
    if (strcmp(directive, "ZCL_APP_RESOURCE") == 0)
        return parse_resource(compile);
    if (strcmp(directive, "ZCL_APP_TOPIC") == 0)
        return parse_topic(compile);
    if (strcmp(directive, "ZCL_APP_WEB_MOUNT") == 0)
        return parse_mount(compile);
    if (strcmp(directive, "ZCL_APP_ONION") == 0)
        return parse_onion(compile);
    if (strcmp(directive, "ZCL_APP_ZNAM") == 0)
        return parse_znam(compile);
    if (strcmp(directive, "ZCL_APP_STATE_SCHEMA") == 0)
        return parse_state_schema(compile);
    if (strcmp(directive, "ZCL_APP_SIM") == 0)
        return parse_sim(compile);
    return parser_error(&compile->parser, APP_DEF_SYNTAX,
                        "unknown directive '%s'", directive);
}

static struct zcl_result definition_semantic_validate(
    struct app_definition_compile *compile)
{
    struct zcl_app_definition_v1 *definition = &compile->definition;
    struct app_definition_parser *parser = &compile->parser;
    uint64_t caps = definition->required_capabilities;
    if (!compile->app_seen)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "missing ZCL_APP directive");
    if (caps == 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "app declares no capabilities");

    bool resident = (caps & ZCL_APP_CAP_RESIDENT_STATE) != 0;
    if (definition->resource_count > 0 && !resident)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "resources require RESIDENT_STATE capability");
    if (definition->resource_count > 0 && !definition->state_schema_declared)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "resources require a state schema");
    if (definition->state_schema_declared && !resident)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "state schema requires RESIDENT_STATE capability");
    if (resident && (!definition->state_schema_declared ||
                     definition->resource_count == 0))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "RESIDENT_STATE requires schema and resources");

    bool web = (caps & ZCL_APP_CAP_WEB_ROUTES) != 0;
    if (definition->mount_count > 0 && !web)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "web mounts require WEB_ROUTES capability");
    if (web && definition->mount_count == 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "WEB_ROUTES capability lacks a web mount");

    bool onion = (caps & ZCL_APP_CAP_ONION_BINDING) != 0;
    if (definition->onion_enabled && (!onion || !web ||
                                     definition->mount_count == 0))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "enabled onion binding requires ONION_BINDING and web route");
    if (onion && (!definition->onion_declared || !definition->onion_enabled))
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "ONION_BINDING capability conflicts with disabled binding");

    bool znam = (caps & ZCL_APP_CAP_ZNAM_BINDING) != 0;
    if (definition->znam_declared && !znam)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "ZNAM binding requires ZNAM_BINDING capability");
    if (znam && !definition->znam_declared)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "ZNAM_BINDING capability lacks a ZNAM binding");

    bool p2p = (caps & ZCL_APP_CAP_P2P_TOPICS) != 0;
    if (definition->topic_count > 0 && !p2p)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "topics require P2P_TOPICS capability");
    if (p2p && definition->topic_count == 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "P2P_TOPICS capability lacks a topic");
    if (definition->topic_count > 0 &&
        (caps & ZCL_APP_CAP_SIGNED_EVENTS) == 0)
        return parser_error(parser, APP_DEF_SEMANTIC,
                            "P2P topics require SIGNED_EVENTS capability");
    return ZCL_OK;
}

struct zcl_result zcl_app_definition_parse_v1(
    const char *expected_app_id,
    const char *source,
    size_t source_len,
    struct zcl_app_definition_v1 *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!out || !source ||
        !zcl_app_definition_id_valid_v1(expected_app_id))
        return ZCL_ERR(APP_DEF_INVALID_ARGUMENT,
                       "invalid app definition parser argument or path id");
    if (source_len == 0 || source_len > ZCL_APP_DEFINITION_SOURCE_MAX)
        return ZCL_ERR(APP_DEF_LIMIT, "app definition source size is invalid");
    if (memchr(source, '\0', source_len) != NULL)
        return ZCL_ERR(APP_DEF_SYNTAX,
                       "app definition contains an embedded NUL byte");

    struct app_definition_compile compile;
    memset(&compile, 0, sizeof(compile));
    compile.parser.source = source;
    compile.parser.source_len = source_len;
    compile.parser.line = 1;
    compile.definition.struct_size = sizeof(compile.definition);
    compile.definition.definition_version = ZCL_APP_DEFINITION_V1;

    while (true) {
        struct zcl_result result = parser_skip_trivia(&compile.parser);
        if (!result.ok)
            return result;
        if (compile.parser.offset == compile.parser.source_len)
            break;
        if (++compile.parser.directive_count >
            ZCL_APP_DEFINITION_DIRECTIVE_MAX)
            return parser_error(&compile.parser, APP_DEF_LIMIT,
                                "too many directives");
        char directive[64];
        result = parser_identifier(&compile.parser, directive,
                                   sizeof(directive));
        if (!result.ok)
            return result;
        result = parse_directive(&compile, expected_app_id, directive);
        if (!result.ok)
            return result;
    }
    struct zcl_result result = definition_semantic_validate(&compile);
    if (!result.ok)
        return result;
    *out = compile.definition;
    return ZCL_OK;
}
