//go:build frida && cgo && linux

#include "bridge.h"

extern void goFridaDetached(uintptr_t id, char *reason);
extern void goFridaMessage(uintptr_t id, char *message, void *data, size_t size);
extern void goFridaDestroyed(uintptr_t id);

const gchar *fm_detach_reason(FridaSessionDetachReason reason) {
  switch (reason) {
    case FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED: return "application_requested";
    case FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED: return "process_replaced";
    case FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED: return "process_terminated";
    case FRIDA_SESSION_DETACH_REASON_CONNECTION_TERMINATED: return "connection_terminated";
    case FRIDA_SESSION_DETACH_REASON_DEVICE_LOST: return "device_lost";
    default: return "unknown";
  }
}

static void on_detached(FridaSession *session, FridaSessionDetachReason reason,
                        FridaCrash *crash, gpointer data) {
  (void)session; (void)crash;
  goFridaDetached((uintptr_t)data, (char *)fm_detach_reason(reason));
}

static void on_message(FridaScript *script, const gchar *message, GBytes *bytes,
                       gpointer data) {
  (void)script;
  gsize size = 0;
  gconstpointer payload = bytes != NULL ? g_bytes_get_data(bytes, &size) : NULL;
  goFridaMessage((uintptr_t)data, (char *)message, (void *)payload, size);
}

static void on_destroyed(FridaScript *script, gpointer data) {
  (void)script;
  goFridaDestroyed((uintptr_t)data);
}

gulong fm_connect_detached(FridaSession *session, uintptr_t id) {
  return g_signal_connect_data(session, "detached", G_CALLBACK(on_detached),
                               (gpointer)id, NULL, 0);
}
gulong fm_connect_message(FridaScript *script, uintptr_t id) {
  return g_signal_connect_data(script, "message", G_CALLBACK(on_message),
                               (gpointer)id, NULL, 0);
}
gulong fm_connect_destroyed(FridaScript *script, uintptr_t id) {
  return g_signal_connect_data(script, "destroyed", G_CALLBACK(on_destroyed),
                               (gpointer)id, NULL, 0);
}
