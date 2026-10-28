#ifndef FRIDA_MCP_BRIDGE_H
#define FRIDA_MCP_BRIDGE_H

#include <frida-core.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

gulong fm_connect_detached(FridaSession *session, uintptr_t id);
gulong fm_connect_message(FridaScript *script, uintptr_t id);
gulong fm_connect_destroyed(FridaScript *script, uintptr_t id);
const gchar *fm_detach_reason(FridaSessionDetachReason reason);

#endif
