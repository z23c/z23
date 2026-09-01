#include "json/json.h"

#include <string.h>

int main(void)
{
    static const char text[] = "{\"count\":3,\"ok\":true,\"name\":\"commons\"}";
    struct json_value value;
    json_init(&value);
    if (!json_read(&value, text, sizeof(text) - 1u) ||
        value.type != JSON_OBJ ||
        json_get_int(json_get(&value, "count")) != 3 ||
        !json_get_bool(json_get(&value, "ok")) ||
        strcmp(json_get_str(json_get(&value, "name")), "commons") != 0) {
        json_free(&value);
        return 1;
    }
    char encoded[128];
    size_t len = json_write(&value, encoded, sizeof(encoded));
    json_free(&value);
    return len >= sizeof(encoded) || strstr(encoded, "commons") == NULL;
}
