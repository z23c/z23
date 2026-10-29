/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void)
{
    char line[131072];
    while (fgets(line, sizeof(line), stdin)) {
        if (strstr(line, "\"method\":\"initialize\"")) puts("{\"id\":1,\"result\":{}}");
        else if (strstr(line, "\"method\":\"account/read\"")) {
            if (getenv("BRIDGE_MOCK_APIKEY")) puts("{\"id\":2,\"result\":{\"account\":{\"type\":\"apiKey\"}}}");
            else puts("{\"id\":2,\"result\":{\"account\":{\"type\":\"chatgpt\"}}}");
        } else if (strstr(line, "\"method\":\"thread/start\"")) puts("{\"id\":3,\"result\":{\"thread\":{\"id\":\"t\"}}}");
        else if (strstr(line, "\"method\":\"turn/start\"")) {
            puts("{\"id\":4,\"result\":{\"turn\":{\"id\":\"x\"}}}");
            puts("{\"method\":\"item/agentMessage/delta\",\"params\":{\"threadId\":\"t\",\"delta\":\"mock answer\"}}");
            if (getenv("BRIDGE_MOCK_FAILED")) puts("{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"t\",\"turn\":{\"status\":\"failed\"}}}");
            else puts("{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"t\",\"turn\":{\"status\":\"completed\"}}}");
        }
        fflush(stdout);
    }
    return 0;
}
