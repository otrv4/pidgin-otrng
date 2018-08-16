/* Purple headers */
#include <account.h>
#include <plugin.h>

#include <libotr-ng/prekey_client.h>

#ifndef OTRNG_PIDGIN_PREKEY_PLUGIN
#define OTRNG_PIDGIN_PREKEY_PLUGIN

typedef struct {
  PurpleAccount *account;
  char *message;
  char *recipient;
} otrng_plugin_offline_message_ctx;

otrng_prekey_client_s *otrng_plugin_get_prekey_client(PurpleAccount *account);

gboolean otrng_prekey_plugin_load(PurplePlugin *handle);
gboolean otrng_prekey_plugin_unload(PurplePlugin *handle);

#endif
