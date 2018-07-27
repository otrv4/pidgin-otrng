/* Purple headers */
#include "plugin.h"

/* libpurple */
#include "account.h"

#include <libotr-ng/prekey_client.h>

#ifndef OTRNG_PIDGIN_PREKEY_PLUGIN
#define OTRNG_PIDGIN_PREKEY_PLUGIN

otrng_prekey_client_s *otrng_plugin_get_prekey_client(PurpleAccount *account);
gboolean otrng_plugin_receive_prekey_protocol_message(char **tosend,
                                                      const char *server,
                                                      const char *message,
                                                      PurpleAccount *account);

gboolean otrng_prekey_plugin_load(PurplePlugin *handle);
gboolean otrng_prekey_plugin_unload(PurplePlugin *handle);

#endif
